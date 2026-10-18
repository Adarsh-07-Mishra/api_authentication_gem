module ApiAuthenticationGem
  class Configuration
    attr_accessor :secret_key,
                  :user_class,
                  :email_attribute,
                  :password_attribute,
                  :identifier,
                  :password_verify_method,
                  :token_expiry,
                  :min_password_length,
                  # --- Tier 1 ---
                  :refresh_tokens_enabled,
                  :refresh_token_expiry,
                  :revocation_enabled,
                  :password_reset_expiry,
                  :lockout_enabled,
                  :max_login_attempts,
                  :lockout_duration,
                  # --- Tier 2: RBAC ---
                  :role_attribute,
                  # --- Tier 2: Magic Link ---
                  :magic_link_enabled,
                  :magic_link_expiry,
                  # --- Tier 2: Session Tracking ---
                  :session_tracking_enabled,
                  # --- Tier 2: Hooks ---
                  :on_signup,
                  :on_login,
                  :on_login_failure,
                  :on_logout,
                  :on_password_reset,
                  # --- Tier 2: Algorithm (HS256 or RS256) ---
                  :algorithm,
                  :private_key,
                  :public_key

    def initialize
      # Core
      @secret_key             = ENV["API_AUTH_SECRET_KEY"]
      @user_class             = "User"
      @email_attribute        = :email
      @password_attribute     = :password
      @identifier             = :email
      @password_verify_method = :authenticate
      @token_expiry           = 24 * 60 * 60
      @min_password_length    = 6

      # Tier 1
      @refresh_tokens_enabled = false
      @refresh_token_expiry   = 30 * 24 * 60 * 60
      @revocation_enabled     = false
      @password_reset_expiry  = 15 * 60
      @lockout_enabled        = false
      @max_login_attempts     = 5
      @lockout_duration       = 15 * 60

      # Tier 2: RBAC
      @role_attribute         = :role

      # Tier 2: Magic Link
      @magic_link_enabled     = false
      @magic_link_expiry      = 15 * 60

      # Tier 2: Session Tracking
      @session_tracking_enabled = false

      # Tier 2: Hooks (nil = disabled)
      @on_signup              = nil
      @on_login               = nil
      @on_login_failure       = nil
      @on_logout              = nil
      @on_password_reset      = nil

      # Tier 2: Algorithm
      @algorithm              = "HS256"
      @private_key            = nil
      @public_key             = nil
    end

    def validate!
      if algorithm == "HS256"
        if secret_key.nil? || secret_key.to_s.strip.empty?
          raise ConfigurationError,
                "secret_key must be set. Use ENV['API_AUTH_SECRET_KEY'] or set it explicitly."
        end
      elsif algorithm == "RS256"
        raise ConfigurationError, "private_key must be an OpenSSL::PKey::RSA instance for RS256" \
          unless private_key.is_a?(OpenSSL::PKey::RSA)
        raise ConfigurationError, "public_key must be an OpenSSL::PKey::RSA instance for RS256" \
          unless public_key.is_a?(OpenSSL::PKey::RSA)
      else
        raise ConfigurationError, "algorithm must be 'HS256' or 'RS256' (got '#{algorithm}')."
      end

      if token_expiry.to_i <= 0
        raise ConfigurationError, "token_expiry must be a positive integer (seconds)."
      end
      if min_password_length.to_i <= 0
        raise ConfigurationError, "min_password_length must be a positive integer."
      end
      if refresh_tokens_enabled && refresh_token_expiry.to_i <= 0
        raise ConfigurationError, "refresh_token_expiry must be a positive integer (seconds)."
      end
      if lockout_enabled && max_login_attempts.to_i <= 0
        raise ConfigurationError, "max_login_attempts must be a positive integer."
      end
      if lockout_enabled && lockout_duration.to_i <= 0
        raise ConfigurationError, "lockout_duration must be a positive integer (seconds)."
      end
      if password_reset_expiry.to_i <= 0
        raise ConfigurationError, "password_reset_expiry must be a positive integer (seconds)."
      end
      if magic_link_enabled && magic_link_expiry.to_i <= 0
        raise ConfigurationError, "magic_link_expiry must be a positive integer (seconds)."
      end
    end
  end
end
