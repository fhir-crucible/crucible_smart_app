# You should never deactivate SSL Peer Verification
# except in terrible development situations using invalid certificates:
# OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE

require 'yaml'
require 'sinatra'
require 'fhir_client'
require 'rest-client'
require 'time_difference'

Dir.glob(File.join(File.dirname(File.absolute_path(__FILE__)),'lib','**','*.rb')).each do |file|
  require file
end

enable :sessions
set :session_secret, SecureRandom.uuid

# Root: redirect to /index
get '/' do
  status, headers, body = call! env.merge("PATH_INFO" => '/index')
end

# The index displays the available endpoints
get '/index' do
  response = Crucible::App::Html.new
  bullets = {
    "#{response.base_url}/index" => 'this page',
    "#{response.base_url}/app" => 'the app (also the redirect_uri after authz)',
    "#{response.base_url}/launch" => 'the launch url',
    "#{response.base_url}/config" => 'configure client ID and scopes'
  }
  response.open.echo_hash('End Points',bullets)

  body response.instructions.close
end

# This is the primary endpoint of the app and the OAuth2 redirect URL
get '/app' do
stream :keep_open do |out|
  response = Crucible::App::Html.new(out)
  if params['error']
    if params['error_uri']
      redirect params['error_uri']
    else
      response.open.echo_hash('Invalid Launch!',params).close
    end
  elsif params['state'] != session[:state]
    response.open
    response.echo_hash('OAuth2 Redirect Parameters',params)
    response.echo_hash('Session State',session)
    response.start_table('Errors',['Status','Description','Detail'])
    message = 'The <span>state</span> parameter did not match the session <span>state</span> set at launch.
              <br/>&nbsp;<br/>
              Please read the <a href="http://docs.smarthealthit.org/authorization/">SMART "launch sequence"</a> for more information.'
    response.assert('Invalid Launch State',false,message).end_table
    response.instructions.close
  elsif params['state'].nil? || params['code'].nil? || session[:client_id].nil? || session[:token_url].nil? || session[:fhir_url].nil?
    response.open
    response.echo_hash('OAuth2 Redirect Parameters',params)
    response.echo_hash('Session State',session)
    response.start_table('Errors',['Status','Description','Detail'])
    message = 'The <span>/app</span> endpoint requires <span>code</span> and <span>state</span> parameters.
              <br/>&nbsp;<br/>
              The session state should also have been set at <span>/launch</span> with <span>client_id</span>, <span>token_url</span>, and <span>fhir_url</span> information.
              <br/>&nbsp;<br/>
               Please read the <a href="http://docs.smarthealthit.org/authorization/">SMART "launch sequence"</a> for more information.'
    response.assert('OAuth2 Launch Parameters',false,message).end_table
    response.instructions.close
  else
    start_time = Time.now
    # Get the OAuth2 token
    puts "App Params: #{params}"

    oauth2_params = {
      'grant_type' => 'authorization_code',
      'code' => params['code'],
      'redirect_uri' => Crucible::App::Config::CONFIGURATION['redirect_url'],
      'client_id' => session[:client_id]
    }
    puts "Token Params: #{oauth2_params}"
    token_response = RestClient.post(session[:token_url], oauth2_params)
    token_response = JSON.parse(token_response.body)
    puts "Token Response: #{token_response}"
    token = token_response['access_token']
    patient_id = token_response['patient']
    scopes = token_response['scope']

    # Begin outputting the response body
    response.open
    response.echo_hash('OAuth2 Redirect Parameters',params)
    response.echo_hash('Token Response',token_response)
    response.start_table('Crucible Test Results',['Status','Description','Detail'])

    # Configure the FHIR Client
    client = FHIR::Client.new(session[:fhir_url])
    version = client.detect_version
    client.set_bearer_token(token)
    client.default_json

    # Get the patient demographics
    if version == :dstu2
      patient = client.read(FHIR::DSTU2::Patient, patient_id).resource
      response.assert('Patient Successfully Retrieved',patient.is_a?(FHIR::DSTU2::Patient),patient.id)
    elsif version == :stu3
      patient = client.read(FHIR::Patient, patient_id).resource
      response.assert('Patient Successfully Retrieved',patient.is_a?(FHIR::Patient),patient.id)
    end
    patient_details = patient.to_hash
    puts "Patient: #{patient_details['id']} #{patient_details['name']}"

    # DAF/US-Core CCDS
    response.assert('Patient Name',patient_details['name'],patient_details['name'])
    response.assert('Patient Gender',patient_details['gender'],patient_details['gender'])
    response.assert('Patient Date of Birth',patient_details['birthDate'],patient_details['birthDate'])
    # US Extensions
    puts 'Examining Patient for US-Core Extensions'
    extensions = {
      'Race' => 'http://hl7.org/fhir/StructureDefinition/us-core-race',
      'Ethnicity' => 'http://hl7.org/fhir/StructureDefinition/us-core-ethnicity',
      'Religion' => 'http://hl7.org/fhir/StructureDefinition/us-core-religion',
      'Mother\'s Maiden Name' => 'http://hl7.org/fhir/StructureDefinition/patient-mothersMaidenName',
      'Birth Place' => 'http://hl7.org/fhir/StructureDefinition/birthPlace'
    }
    required_extensions = ['Race','Ethnicity']
    extensions.each do |name,url|
      detail = nil
      check = :not_found
      if patient_details['extension']
        detail = patient_details['extension'].find{|e| e['url']==url }
        check = !detail.nil? if required_extensions.include?(name)
      elsif required_extensions.include?(name)
        check = false
      end
      response.assert("Patient #{name}", check, detail)
    end
    response.assert('Patient Preferred Language',(patient_details['communication'] && patient_details['communication'].find{|c|c['language'] && c['preferred']}),patient_details['communication'])

    # Get the patient's smoking status
    # {"coding":[{"system":"http://loinc.org","code":"72166-2"}]}
    puts 'Getting Smoking Status'
    if version == :dstu2
      search_reply = client.search(FHIR::DSTU2::Observation, search: { parameters: { 'patient' => patient_id, 'code' => 'http://loinc.org|72166-2'}})
    elsif version == :stu3
      search_reply = client.search(FHIR::Observation, search: { parameters: { 'patient' => patient_id, 'code' => 'http://loinc.org|72166-2'}})
    end
    detail = search_reply.resource.entry.first.to_fhir_json rescue nil
    response.assert('Smoking Status',((search_reply.resource.entry.length >= 1) rescue false),detail)

    # Get the patient's allergies
    # There should be at least one. No known allergies should have a negated entry.
    # Include these codes as defined in http://snomed.info/sct
    #   Code	     Display
    #   160244002	No Known Allergies
    #   429625007	No Known Food Allergies
    #   409137002	No Known Drug Allergies
    #   428607008	No Known Environmental Allergy
    puts 'Getting AllergyIntolerances'
    if version == :dstu2
      search_reply = client.search(FHIR::DSTU2::AllergyIntolerance, search: { parameters: { 'patient' => patient_id } })
    elsif version == :stu3
      search_reply = client.search(FHIR::AllergyIntolerance, search: { parameters: { 'patient' => patient_id } })
    end
    response.assert_search_results('AllergyIntolerances',search_reply)
    begin
      if search_reply.resource.entry.length==0
        response.assert('No Known Allergies',false)
      else
        response.assert('No Known Allergies',:skip,'Skipped because AllergyIntolerances were found.')
      end
    rescue
      response.assert('No Known Allergies',false)
    end

    # Vital Signs Searching
    if version == :dstu2
      # Vital Signs includes these codes as defined in http://loinc.org
      vital_signs = {
        '9279-1' => 'Respiratory rate',
        '8867-4' => 'Heart rate',
        '2710-2' => 'Oxygen saturation in Capillary blood by Oximetry',
        '55284-4' => 'Blood pressure systolic and diastolic',
        '8480-6' => 'Systolic blood pressure',
        '8462-4' => 'Diastolic blood pressure',
        '8310-5' => 'Body temperature',
        '8302-2' => 'Body height',
        '8306-3' => 'Body height --lying',
        '8287-5' => 'Head Occipital-frontal circumference by Tape measure',
        '3141-9' => 'Body weight Measured',
        '39156-5' => 'Body mass index (BMI) [Ratio]',
        '3140-1' => 'Body surface area Derived from formula',
        '59408-5' => 'Oxygen saturation in Arterial blood by Pulse oximetry',
        '8478-0' => 'Mean blood pressure'
      }
    elsif version == :stu3
      # Vital Signs includes these codes as defined in http://hl7.org/fhir/STU3/observation-vitalsigns.html
      vital_signs = {
        '85353-1' => 'Vital signs, weight, height, head circumference, oxygen saturation and BMI panel',
        '9279-1' => 'Respiratory Rate',
        '8867-4' => 'Heart rate',
        '59408-5' => 'Oxygen saturation in Arterial blood by Pulse oximetry',
        '8310-5' => 'Body temperature',
        '8302-2' => 'Body height',
        '8306-3' => 'Body height --lying',
        '8287-5' => 'Head Occipital-frontal circumference by Tape measure',
        '29463-7' => 'Body weight',
        '39156-5' => 'Body mass index (BMI) [Ratio]',
        '85354-9' => 'Blood pressure systolic and diastolic',
        '8480-6' => 'Systolic blood pressure',
        '8462-4' => 'Diastolic blood pressure'
      }
    end
    puts 'Getting Vital Signs / Observations'
    vital_signs.each do |code,display|
      if version == :dstu2
        search_reply = client.search(FHIR::DSTU2::Observation, search: { parameters: { 'patient' => patient_id, 'code' => "http://loinc.org|#{code}" } })
      elsif version == :stu3
        search_reply = client.search(FHIR::Observation, search: { parameters: { 'patient' => patient_id, 'code' => "http://loinc.org|#{code}" } })
      end
      response.assert_search_results("Vital Sign: #{display}",search_reply)
    end

    puts 'Checking for Supporting Resources'
    if version == :dstu2
      supporting_resources = [
        FHIR::DSTU2::CarePlan, FHIR::DSTU2::Condition, FHIR::DSTU2::DiagnosticOrder,
        FHIR::DSTU2::DiagnosticReport, FHIR::DSTU2::Encounter,
        FHIR::DSTU2::FamilyMemberHistory,FHIR::DSTU2::Goal, FHIR::DSTU2::Immunization,
        FHIR::DSTU2::List, FHIR::DSTU2::Procedure, FHIR::DSTU2::MedicationAdministration,
        FHIR::DSTU2::MedicationDispense,FHIR::DSTU2::MedicationOrder,
        FHIR::DSTU2::MedicationStatement, FHIR::DSTU2::RelatedPerson
      ]
    elsif version == :stu3
      supporting_resources = [
        FHIR::CarePlan, FHIR::CareTeam, FHIR::Condition, FHIR::Device,
        FHIR::DiagnosticReport, FHIR::Goal, FHIR::Immunization, FHIR::MedicationRequest,
        FHIR::MedicationStatement, FHIR::Procedure, FHIR::RelatedPerson, FHIR::Specimen
      ]
    end
    supporting_resources.each do |klass|
      puts "Getting #{klass.name.demodulize}s"
      search_reply = client.search(klass, search: { parameters: { 'patient' => patient_id } })
      response.assert_search_results("#{klass.name.demodulize}s",search_reply)
    end

    # DAF (DSTU2)-----------------------------
#    # AllergyIntolerance
#    # DiagnosticOrder
#    # DiagnosticReport
#    # Encounter
#    # FamilyMemberHistory
#    # Immunization
    # Results (Observation)
    # Medication
#    # MedicationStatement
#    # MedicationAdministration
#    # MedicationDispense
#    # MedicationOrder
#    # Patient
#    # Condition
#    # Procedure
#    # SmokingStatus (Observation)
#    # VitalSigns (Observation)
    # List
#    # Additional Resources: RelatedPerson, Specimen

    # US Core (STU3)-----------------------------
    # AllergyIntolerance
    # CareTeam
    # Condition
    # Device
    # DiagnosticReport
    # Goal
    # Immunization
    # Location (can't search by patient)
    # Medication (can't search by patient)
    # MedicationRequest
    # MedicationStatement
    # Practitioner (can't search by patient)
    # Procedure
    # Results (Observation)
    # SmokingStatus (Observation
    # CarePlan
    # Organization (can't search by patient)
    # Patient
    # VitalSigns (Observation)
    # Additional Resources: RelatedPerson, Specimen

    # ARGONAUTS ----------------------
    # 	CCDS Data Element	         FHIR Resource
#    # (1)	Patient Name	             Patient
#    # (2)	Sex	                        Patient
#    # (3)	Date of birth	              Patient
#    # (4)	Race	                       Patient
#    # (5)	Ethnicity	                  Patient
#    # (6)	Preferred language	       Patient
#    # (7)	Smoking status	           Observation
#    # (8)	Problems	                 Condition
#    # (9)	Medications	                Medication, MedicationStatement, MedicationOrder
#    # (10)	Medication allergies	    AllergyIntolerance
#    # (11)	Laboratory test(s)	      Observation, DiagnosticReport
#    # (12)	Laboratory value(s)/result(s)	Observation, DiagnosticReport
#    # (13)	Vital signs	             Observation
    # (14)	(no longer required)	-
#    # (15)	Procedures	              Procedure
#    # (16)	Care team member(s)	     CarePlan
#    # (17)	Immunizations	           Immunization
    # (18)	Unique device identifier(s) for a patient’s implantable device(s)	Device
#    # (19)	Assessment and plan of treatment	CarePlan
#    # (20)	Goals	                   Goal
#    # (21)	Health concerns	         Condition
    # --------------------------------
    # Date range search requirements are included in the Quick Start section for the following resources -
    # Vital Signs, Laboratory Results, Goals, Procedures, and Assessment and Plan of Treatment.

    # Output a summary
    total = response.pass + response.not_found + response.skip + response.fail
    response.assert("#{((response.pass.to_f / total.to_f)*100.0).round}% (#{response.pass} of #{total})",true,'Total tests passed')
    response.assert("#{((response.not_found.to_f / total.to_f)*100.0).round}% (#{response.not_found} of #{total})",:not_found,'Total tests "not found" or inconclusive')
    response.assert("#{((response.skip.to_f / total.to_f)*100.0).round}% (#{response.skip} of #{total})",:skip,'Total tests skipped')
    response.assert("#{((response.fail.to_f / total.to_f)*100.0).round}% (#{response.fail} of #{total})",false,'Total tests failed')
    response.end_table

    # Output the time spent
    end_time = Time.now
    response.output "</div><div><br/><p>Tests completed in #{TimeDifference.between(start_time,end_time).humanize}.</p><br/>"
    response.close
  end
  out.close
end
end

# Helper method to wrap a resource in a Bundle.entry
def bundle_entry(resource)
  entry = FHIR::Bundle::BundleEntryComponent.new
  entry.resource = resource
  entry
end

# This is the launch URI that redirects to an Authorization server
get '/launch' do
  if params && params['iss'] && params['launch']
    client_id = Crucible::App::Config.get_client_id(params['iss'])
    auth_info = Crucible::App::Config.get_auth_info(params['iss'])
    session[:client_id] = client_id
    session[:fhir_url] = params['iss']
    session[:authorize_url] = auth_info[:authorize_url]
    session[:token_url] = auth_info[:token_url]
    puts "Launch Client ID: #{client_id}\nLaunch Auth Info: #{auth_info}\nLaunch Redirect: #{Crucible::App::Config::CONFIGURATION['redirect_url']}"
    session[:state] = SecureRandom.uuid
    oauth2_params = {
      'response_type' => 'code',
      'client_id' => client_id,
      'redirect_uri' => Crucible::App::Config::CONFIGURATION['redirect_url'],
      'scope' => Crucible::App::Config.get_scopes(params['iss']),
      'launch' => params['launch'],
      'state' => session[:state],
      'aud' => params['iss']
    }
    oauth2_auth_query = "#{session[:authorize_url]}?"
    oauth2_params.each do |key,value|
      oauth2_auth_query += "#{key}=#{CGI.escape(value)}&"
    end
    puts "Launch Authz Query: #{oauth2_auth_query[0..-2]}"
    redirect oauth2_auth_query[0..-2]
  else
    response = Crucible::App::Html.new
    response.open.echo_hash('params',params)
    response.start_table('Errors',['Status','Description','Detail'])
    message = 'The <span>/launch</span> endpoint requires <span>iss</span> and <span>launch</span> parameters.
              <br/>&nbsp;<br/>
               Please read the <a href="http://docs.smarthealthit.org/authorization/">SMART "launch sequence"</a> for more information.'
    response.assert('OAuth2 Launch Parameters',false,message).end_table
    body response.instructions.close
  end
end

get '/config' do
  response = Crucible::App::Html.new
  response.open
  response.start_table('Configuration',['Server','Client ID','Scopes',''])
  Crucible::App::Config.get_config.each do |row|
    delete_button = "<form method=\"POST\" action=\"#{response.base_url}/config\"><input type=\"hidden\" name=\"delete\" value=\"#{row.first}\"><input type=\"submit\" value=\"Delete\"></form>"
    response.add_table_row(row << delete_button)
  end
  response.end_table
  fields = { 'Server' => '', 'Client ID' => '', 'Scopes' => 'launch openid profile patient/*.read'}
  response.add_form('Add New Configuration','/config',fields)
  body response.close
end

post '/config' do
  if params['delete']
    puts "Deleting configuration: #{params['delete']}"
    Crucible::App::Config.delete_client(params['delete'])
  else
    puts "Saving configuration: #{params}"
    Crucible::App::Config.add_client(params['Server'],params['Client ID'],params['Scopes'])
  end
  puts "Configuration saved."
  redirect "#{Crucible::App::Html.new.base_url}/config"
end
