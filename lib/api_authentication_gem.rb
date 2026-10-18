require "active_record"
require "api_authentication_gem/version"
require "api_authentication_gem/errors"
require "api_authentication_gem/configuration"
require "api_authentication_gem/models/refresh_token"
require "api_authentication_gem/models/revoked_token"
require "api_authentication_gem/models/password_reset"
require "api_authentication_gem/models/lockout"
require "api_authentication_gem/models/magic_link"
require "api_authentication_gem/models/auth_session"
require "api_authentication_gem/auth"
require "api_authentication_gem/concerns/authenticatable"

module ApiAuthenticationGem
  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield(configuration)
    configuration.validate!
  end

  def self.reset_configuration!
    @configuration = nil
  end
end
