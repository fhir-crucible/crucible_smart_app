class TestingInstance
  include DataMapper::Resource
  property :id, String, key: true, default: proc { SecureRandomBase62.generate(64) }
  property :url, String
  property :name, String
  property :client_id, String
  property :base_url, String

  property :client_name, String
  property :scopes, String
  property :launch_type, String
  property :state, String

  property :conformance_checked, Boolean
  property :oauth_authorize_endpoint, String
  property :oauth_token_endpoint, String
  property :oauth_register_endpoint, String
  property :fhir_format, String

  property :dynamically_registered, Boolean
  property :client_endpoint_key, String, default: proc { SecureRandomBase62.generate(32) }

  property :token, String
  property :token_retrieved_at, DateTime
  property :id_token, String
  property :created_at, DateTime, default: proc { DateTime.now }
  property :issuer, String

  property :oauth_introspection_endpoint, String
  property :resource_id, String
  property :resource_secret, String
  property :introspect_token, String

  has n, :sequence_results
  has n, :supported_resources, order: [:index.asc]
  has n, :resource_references

  def latest_results
    self.sequence_results.reduce({}) do |hash, result|
      if hash[result.name].nil? || hash[result.name].created_at < result.created_at
        hash[result.name] = result
      end
      hash
    end
  end

  def waiting_on_sequence
    self.sequence_results.first(result: 'wait')
  end

  def final_result

    required_sequences = SequenceBase.subclasses.reject(&:optional?)

    all_passed = required_sequences.all? do |sequence|
      self.latest_results[sequence.name].try(:result) == 'pass'
    end

    if all_passed
      return 'pass'
    else
      return 'fail'
    end

  end

  def patient_id
    self.resource_references.select{|ref| ref.resource_type == 'Patient'}.first.try(:resource_id)
  end

  def save_supported_resources(conformance)

    resources = ['Patient',
                 'AllergyIntolerance',
                 'CarePlan',
                 'Condition',
                 'Device',
                 'DocumentReference',
                 'Goal',
                 'DiagnosticReport',
                 'Immunization',
                 'Medication',
                 'MedicationStatement',
                 'MedicationOrder',
                 'Observation',
                 'Procedure']

    supported_resources = conformance.rest.first.resource.select{ |r| resources.include? r.type}.reduce({}){|a,k| a[k.type] = k; a}

    self.supported_resources.each(&:destroy)
    self.save!

    resources.each_with_index do |resource_name, index|

      resource = supported_resources[resource_name]

      read_supported = resource && resource.interaction && resource.interaction.any?{|i| i.code == 'read'}

      self.supported_resources << SupportedResource.create({
        resource_type: resource_name,
        index: index,
        testing_instance_id: self.id,
        supported: !resource.nil?,
        read_supported: read_supported,
        vread_supported: resource && resource.interaction && resource.interaction.any?{|i| i.code == 'vread'},
        search_supported: resource && resource.interaction && resource.interaction.any?{|i| i.code == 'search-type'},
        history_supported: resource && resource.interaction && resource.interaction.any?{|i| i.code == 'history-instance'}
      })
    end

    self.save!

  end

  def conformance_supported?(resource, methods = [])

    resource_support = self.supported_resources.find {|r| r.resource_type == resource.to_s}
    return false if resource_support.nil? || !resource_support.supported

    methods.all? do |method|
      case method
      when :read
        resource_support.read_supported
      when :search
        resource_support.search_supported
      when :history
        resource_support.history_supported
      when :vread
        resource_support.vread_supported
      else
        false
      end
    end

  end

end
