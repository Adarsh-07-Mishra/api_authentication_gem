module ApiAuthenticationGem
  class Configuration
    attr_accessor :secret_key, :user_class

    def initialize
      @secret_key = ENV["API_AUTH_SECRET_KEY"] || "your-default-secret-key"
      @user_class = "User" # Default to 'User' model
    end
  end
end

