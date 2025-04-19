require "api_authentication_gem/version"
require "api_authentication_gem/configuration"
require "api_authentication_gem/auth"

module ApiAuthenticationGem
  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield(configuration)
  end
end
