module ApiAuthenticationGem
  class Error < StandardError; end
  class ConfigurationError < Error; end
  class AuthenticationError < Error; end
end
