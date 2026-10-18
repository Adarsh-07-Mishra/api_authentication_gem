require "jwt"
require "openssl"
require "securerandom"

module ApiAuthenticationGem
  class Auth
    # =========================================================================
    # signup
    # =========================================================================
    # Success: { message:, user:, token:, refresh_token: (if enabled) }
    # Failure: { error: }
    def self.signup(email:, password:, ip_address: nil, user_agent: nil)
      config = ApiAuthenticationGem.configuration

      return { error: "Email is required" } if email.to_s.strip.empty?
      return { error: "Password must be at least #{config.min_password_length} characters" } \
        if password.to_s.length < config.min_password_length

      user_class = config.user_class.constantize
      user = user_class.new(
        config.email_attribute    => email.to_s.strip.downcase,
        config.password_attribute => password
      )

      if user.save
        access_token = generate_access_token(user.id, ip_address: ip_address, user_agent: user_agent)
        result = { message: "User created successfully", user: user, token: access_token }
        result[:refresh_token] = generate_refresh_token_record(user.id).token if config.refresh_tokens_enabled
        call_hook(:on_signup, user)
        result
      else
        { error: user.errors.full_messages.join(", ") }
      end
    rescue ConfigurationError
      raise
    rescue => e
      { error: e.message }
    end

    # =========================================================================
    # login
    # =========================================================================
    # Success: { token:, user:, refresh_token: (if enabled) }
    # Failure: { error: }
    def self.login(email:, password:, ip_address: nil, user_agent: nil)
      return { error: "Email and password are required" } \
        if email.to_s.strip.empty? || password.to_s.strip.empty?

      config     = ApiAuthenticationGem.configuration
      normalized = email.to_s.strip.downcase

      if config.lockout_enabled
        lockout = Lockout.find_or_initialize_by(identifier: normalized)
        if lockout.locked?
          return { error: "Account locked. Try again in #{lockout.minutes_remaining} minute(s)." }
        end
      end

      user_class = config.user_class.constantize
      user       = user_class.find_by(config.identifier => normalized)

      if user.nil?
        record_failed_attempt(normalized) if config.lockout_enabled
        call_hook(:on_login_failure, normalized)
        return { error: "Invalid email or password" }
      end

      unless user.respond_to?(config.password_verify_method)
        raise ConfigurationError, "User model must respond to `#{config.password_verify_method}`"
      end

      unless user.public_send(config.password_verify_method, password)
        record_failed_attempt(normalized) if config.lockout_enabled
        call_hook(:on_login_failure, normalized)
        return { error: "Invalid email or password" }
      end

      clear_lockout(normalized) if config.lockout_enabled

      access_token = generate_access_token(user.id, ip_address: ip_address, user_agent: user_agent)
      result       = { token: access_token, user: user }
      result[:refresh_token] = generate_refresh_token_record(user.id).token if config.refresh_tokens_enabled
      call_hook(:on_login, user)
      result
    rescue ConfigurationError
      raise
    rescue => e
      { error: e.message }
    end

    # =========================================================================
    # refresh
    # =========================================================================
    # Rotates tokens: revokes old refresh token, issues new access + refresh pair.
    # Success: { token:, refresh_token:, user: }
    # Failure: { error: }
    def self.refresh(refresh_token:, ip_address: nil, user_agent: nil)
      return { error: "Refresh token is required" } if refresh_token.to_s.strip.empty?

      config = ApiAuthenticationGem.configuration
      return { error: "Refresh tokens are not enabled" } unless config.refresh_tokens_enabled

      record = RefreshToken.find_by(token: refresh_token)
      return { error: "Invalid refresh token" }          unless record
      return { error: "Refresh token has been revoked" } if     record.revoked_at
      return { error: "Refresh token has expired" }      if     record.expires_at <= Time.now

      record.revoke!

      user_class = config.user_class.constantize
      user       = user_class.find_by(id: record.user_id)
      return { error: "User not found" } unless user

      new_access  = generate_access_token(user.id, ip_address: ip_address, user_agent: user_agent)
      new_refresh = generate_refresh_token_record(user.id)

      { token: new_access, refresh_token: new_refresh.token, user: user }
    rescue => e
      { error: e.message }
    end

    # =========================================================================
    # revoke
    # =========================================================================
    # Success: { message: }
    # Failure: { error: }
    def self.revoke(token:)
      return { error: "Token is required" } if token.to_s.strip.empty?

      config = ApiAuthenticationGem.configuration
      return { error: "Token revocation is not enabled" } unless config.revocation_enabled

      decoded = JWT.decode(token, verification_key, true, { algorithm: config.algorithm }).first

      RevokedToken.find_or_create_by!(jti: decoded["jti"]) do |r|
        r.expires_at = Time.at(decoded["exp"])
      end

      # Mirror into session tracker if enabled
      if config.session_tracking_enabled
        AuthSession.find_by(jti: decoded["jti"])&.revoke!
      end

      call_hook(:on_logout, decoded["jti"])
      { message: "Token revoked successfully" }
    rescue JWT::ExpiredSignature
      { error: "Cannot revoke an already-expired token" }
    rescue JWT::DecodeError
      { error: "Invalid token" }
    rescue => e
      { error: e.message }
    end

    # =========================================================================
    # request_password_reset
    # =========================================================================
    def self.request_password_reset(email:)
      return { error: "Email is required" } if email.to_s.strip.empty?

      config     = ApiAuthenticationGem.configuration
      normalized = email.to_s.strip.downcase
      base_msg   = { message: "If that email is registered, a reset token has been sent." }

      user_class = config.user_class.constantize
      user       = user_class.find_by(config.identifier => normalized)
      return base_msg unless user

      PasswordReset.where(identifier: normalized, used_at: nil).update_all(used_at: Time.now)

      reset = PasswordReset.create!(
        identifier: normalized,
        token:      SecureRandom.urlsafe_base64(32),
        expires_at: Time.now + config.password_reset_expiry
      )

      base_msg.merge(reset_token: reset.token)
    rescue => e
      { error: e.message }
    end

    # =========================================================================
    # reset_password
    # =========================================================================
    def self.reset_password(reset_token:, new_password:)
      return { error: "Reset token is required" } if reset_token.to_s.strip.empty?

      config = ApiAuthenticationGem.configuration

      if new_password.to_s.length < config.min_password_length
        return { error: "Password must be at least #{config.min_password_length} characters" }
      end

      record = PasswordReset.active.find_by(token: reset_token)
      return { error: "Invalid or expired reset token" } unless record

      user_class = config.user_class.constantize
      user       = user_class.find_by(config.identifier => record.identifier)
      return { error: "User not found" } unless user

      if user.update(config.password_attribute => new_password)
        record.consume!
        call_hook(:on_password_reset, user)
        { message: "Password has been reset successfully" }
      else
        { error: user.errors.full_messages.join(", ") }
      end
    rescue => e
      { error: e.message }
    end

    # =========================================================================
    # send_magic_link  (Tier 2)
    # =========================================================================
    # Generates a one-time login token the Rails app can email to the user.
    # DO NOT expose magic_token directly in API responses.
    # Success (known email):   { message:, magic_token: }
    # Success (unknown email): { message: }
    # Failure: { error: }
    def self.send_magic_link(email:)
      return { error: "Email is required" } if email.to_s.strip.empty?

      config = ApiAuthenticationGem.configuration
      return { error: "Magic link login is not enabled" } unless config.magic_link_enabled

      normalized = email.to_s.strip.downcase
      base_msg   = { message: "If that email is registered, a magic link has been sent." }

      user_class = config.user_class.constantize
      user       = user_class.find_by(config.identifier => normalized)
      return base_msg unless user

      # Invalidate any existing unused magic links for this email
      MagicLink.where(identifier: normalized, used_at: nil).update_all(used_at: Time.now)

      link = MagicLink.create!(
        identifier: normalized,
        token:      SecureRandom.urlsafe_base64(32),
        expires_at: Time.now + config.magic_link_expiry
      )

      base_msg.merge(magic_token: link.token)
    rescue => e
      { error: e.message }
    end

    # =========================================================================
    # verify_magic_link  (Tier 2)
    # =========================================================================
    # Validates the one-time token and returns a JWT — no password required.
    # Success: { token:, user:, refresh_token: (if enabled) }
    # Failure: { error: }
    def self.verify_magic_link(token:, ip_address: nil, user_agent: nil)
      return { error: "Magic link token is required" } if token.to_s.strip.empty?

      config = ApiAuthenticationGem.configuration
      return { error: "Magic link login is not enabled" } unless config.magic_link_enabled

      link = MagicLink.active.find_by(token: token)
      return { error: "Invalid or expired magic link" } unless link

      user_class = config.user_class.constantize
      user       = user_class.find_by(config.identifier => link.identifier)
      return { error: "User not found" } unless user

      link.consume!

      access_token = generate_access_token(user.id, ip_address: ip_address, user_agent: user_agent)
      result       = { token: access_token, user: user }
      result[:refresh_token] = generate_refresh_token_record(user.id).token if config.refresh_tokens_enabled
      call_hook(:on_login, user)
      result
    rescue => e
      { error: e.message }
    end

    # =========================================================================
    # active_sessions  (Tier 2)
    # =========================================================================
    # Returns all non-expired, non-revoked sessions for a user.
    # Success: { sessions: [AuthSession, ...] }
    # Failure: { error: }
    def self.active_sessions(user_id:)
      return { error: "Session tracking is not enabled" } \
        unless ApiAuthenticationGem.configuration.session_tracking_enabled

      { sessions: AuthSession.where(user_id: user_id).active.order(created_at: :desc) }
    rescue => e
      { error: e.message }
    end

    # =========================================================================
    # revoke_session  (Tier 2)
    # =========================================================================
    # Revokes a specific session by jti; also adds to the revocation blocklist.
    # Success: { message: }
    # Failure: { error: }
    def self.revoke_session(jti:)
      config = ApiAuthenticationGem.configuration
      return { error: "Session tracking is not enabled" } unless config.session_tracking_enabled
      return { error: "JTI is required" } if jti.to_s.strip.empty?

      session = AuthSession.find_by(jti: jti)
      return { error: "Session not found" } unless session

      session.revoke!

      if config.revocation_enabled
        RevokedToken.find_or_create_by!(jti: jti) { |r| r.expires_at = session.expires_at }
      end

      call_hook(:on_logout, jti)
      { message: "Session revoked successfully" }
    rescue => e
      { error: e.message }
    end

    # =========================================================================
    # revoke_all_sessions  (Tier 2)
    # =========================================================================
    # Revokes every active session for a user — useful after password change or
    # account compromise.
    # Success: { message: "N session(s) revoked" }
    # Failure: { error: }
    def self.revoke_all_sessions(user_id:)
      config = ApiAuthenticationGem.configuration
      return { error: "Session tracking is not enabled" } unless config.session_tracking_enabled

      sessions = AuthSession.where(user_id: user_id).active.to_a
      sessions.each do |s|
        s.revoke!
        if config.revocation_enabled
          RevokedToken.find_or_create_by!(jti: s.jti) { |r| r.expires_at = s.expires_at }
        end
        call_hook(:on_logout, s.jti)
      end

      { message: "#{sessions.count} session(s) revoked" }
    rescue => e
      { error: e.message }
    end

    # =========================================================================
    # decode
    # =========================================================================
    # Returns payload hash, or nil if invalid / expired / revoked.
    def self.decode(token)
      return nil if token.to_s.strip.empty?

      config  = ApiAuthenticationGem.configuration
      decoded = JWT.decode(
        token,
        verification_key,
        true,
        { algorithm: config.algorithm }
      ).first

      return nil if token_revoked?(decoded["jti"])

      decoded
    rescue JWT::ExpiredSignature, JWT::DecodeError
      nil
    end

    # =========================================================================
    private
    # =========================================================================

    def self.signing_key
      config = ApiAuthenticationGem.configuration
      config.algorithm == "RS256" ? config.private_key : config.secret_key
    end

    def self.verification_key
      config = ApiAuthenticationGem.configuration
      config.algorithm == "RS256" ? config.public_key : config.secret_key
    end

    def self.generate_access_token(user_id, ip_address: nil, user_agent: nil)
      config = ApiAuthenticationGem.configuration
      now    = Time.now.to_i
      jti    = SecureRandom.uuid

      payload = {
        sub: user_id,
        iat: now,
        exp: now + config.token_expiry.to_i,
        jti: jti
      }

      if config.session_tracking_enabled
        AuthSession.create!(
          user_id:    user_id,
          jti:        jti,
          ip_address: ip_address,
          user_agent: user_agent,
          expires_at: Time.at(payload[:exp])
        )
      end

      JWT.encode(payload, signing_key, config.algorithm)
    end

    def self.generate_refresh_token_record(user_id)
      config = ApiAuthenticationGem.configuration
      RefreshToken.create!(
        user_id:    user_id,
        token:      SecureRandom.urlsafe_base64(32),
        expires_at: Time.now + config.refresh_token_expiry.to_i
      )
    end

    def self.token_revoked?(jti)
      return false unless ApiAuthenticationGem.configuration.revocation_enabled
      RevokedToken.revoked?(jti)
    end

    def self.record_failed_attempt(identifier)
      config  = ApiAuthenticationGem.configuration
      lockout = Lockout.find_or_initialize_by(identifier: identifier)
      lockout.failed_attempts = (lockout.failed_attempts || 0) + 1
      if lockout.failed_attempts >= config.max_login_attempts
        lockout.locked_until    = Time.now + config.lockout_duration
        lockout.failed_attempts = 0
      end
      lockout.save!
    end

    def self.clear_lockout(identifier)
      Lockout.find_by(identifier: identifier)&.reset!
    end

    def self.call_hook(hook_name, *args)
      hook = ApiAuthenticationGem.configuration.public_send(hook_name)
      hook.call(*args) if hook.respond_to?(:call)
    rescue => _e
      # Hook errors must never interrupt the auth flow
    end
  end
end
