require "rails_helper"

RSpec.describe "Session Tracking — ApiAuthenticationGem::Auth session methods" do
  before do
    ApiAuthenticationGem.reset_configuration!
    ApiAuthenticationGem.configure do |config|
      config.secret_key               = "session-tracking-test-secret"
      config.user_class               = "User"
      config.session_tracking_enabled = true
      config.revocation_enabled       = true
    end
    ApiAuthenticationGem::Auth.signup(email: email, password: password)
  end

  let(:email)    { "sessions@example.com" }
  let(:password) { "securepass" }

  def do_login(extra = {})
    ApiAuthenticationGem::Auth.login(
      email: email, password: password, **extra
    )
  end

  # ---------------------------------------------------------------------------
  # Session created on login
  # ---------------------------------------------------------------------------
  describe "session creation" do
    it "creates an AuthSession record on login" do
      result = do_login
      decoded = ApiAuthenticationGem::Auth.decode(result[:token])
      session = ApiAuthenticationGem::AuthSession.find_by(jti: decoded["jti"])

      expect(session).not_to be_nil
      expect(session.user_id).to eq(result[:user].id)
      expect(session.expires_at).to be > Time.now
      expect(session.revoked_at).to be_nil
    end

    it "stores ip_address and user_agent when provided" do
      result  = do_login(ip_address: "192.168.1.1", user_agent: "Mozilla/5.0")
      decoded = ApiAuthenticationGem::Auth.decode(result[:token])
      session = ApiAuthenticationGem::AuthSession.find_by(jti: decoded["jti"])

      expect(session.ip_address).to eq("192.168.1.1")
      expect(session.user_agent).to eq("Mozilla/5.0")
    end

    it "creates a separate session for each login" do
      do_login
      do_login
      user = User.find_by(email: email)
      expect(ApiAuthenticationGem::AuthSession.where(user_id: user.id).count).to eq(3) # signup + 2 logins
    end

    it "also creates a session on signup" do
      user   = User.find_by(email: email)
      expect(ApiAuthenticationGem::AuthSession.where(user_id: user.id).count).to eq(1)
    end
  end

  # ---------------------------------------------------------------------------
  # active_sessions
  # ---------------------------------------------------------------------------
  describe ".active_sessions" do
    it "returns active sessions for the user" do
      user = User.find_by(email: email)
      do_login
      result = ApiAuthenticationGem::Auth.active_sessions(user_id: user.id)

      expect(result[:error]).to be_nil
      expect(result[:sessions].count).to eq(2) # signup session + login session
    end

    it "does not include revoked sessions" do
      user    = User.find_by(email: email)
      login_r = do_login
      decoded = ApiAuthenticationGem::Auth.decode(login_r[:token])
      ApiAuthenticationGem::AuthSession.find_by(jti: decoded["jti"]).revoke!

      result = ApiAuthenticationGem::Auth.active_sessions(user_id: user.id)
      jti_list = result[:sessions].map(&:jti)
      expect(jti_list).not_to include(decoded["jti"])
    end

    it "does not include expired sessions" do
      user    = User.find_by(email: email)
      login_r = do_login
      decoded = ApiAuthenticationGem::Auth.decode(login_r[:token])
      ApiAuthenticationGem::AuthSession.find_by(jti: decoded["jti"])
        .update!(expires_at: Time.now - 1)

      result   = ApiAuthenticationGem::Auth.active_sessions(user_id: user.id)
      jti_list = result[:sessions].map(&:jti)
      expect(jti_list).not_to include(decoded["jti"])
    end

    it "returns error when session tracking is disabled" do
      ApiAuthenticationGem.configuration.session_tracking_enabled = false
      result = ApiAuthenticationGem::Auth.active_sessions(user_id: 1)
      expect(result[:error]).to eq("Session tracking is not enabled")
    end
  end

  # ---------------------------------------------------------------------------
  # revoke_session
  # ---------------------------------------------------------------------------
  describe ".revoke_session" do
    it "revokes a specific session by jti" do
      login_r = do_login
      decoded = ApiAuthenticationGem::Auth.decode(login_r[:token])
      jti     = decoded["jti"]

      result = ApiAuthenticationGem::Auth.revoke_session(jti: jti)
      expect(result[:message]).to eq("Session revoked successfully")

      session = ApiAuthenticationGem::AuthSession.find_by(jti: jti)
      expect(session.revoked_at).not_to be_nil
    end

    it "adds jti to the revoked_tokens blocklist when revocation is enabled" do
      login_r = do_login
      decoded = ApiAuthenticationGem::Auth.decode(login_r[:token])
      jti     = decoded["jti"]

      ApiAuthenticationGem::Auth.revoke_session(jti: jti)
      expect(ApiAuthenticationGem::RevokedToken.revoked?(jti)).to be true
    end

    it "decode returns nil after session revocation" do
      login_r = do_login
      token   = login_r[:token]
      decoded = ApiAuthenticationGem::Auth.decode(token)

      ApiAuthenticationGem::Auth.revoke_session(jti: decoded["jti"])
      expect(ApiAuthenticationGem::Auth.decode(token)).to be_nil
    end

    it "returns error for an unknown jti" do
      result = ApiAuthenticationGem::Auth.revoke_session(jti: "nonexistent-jti")
      expect(result[:error]).to eq("Session not found")
    end

    it "returns error for blank jti" do
      result = ApiAuthenticationGem::Auth.revoke_session(jti: "")
      expect(result[:error]).to eq("JTI is required")
    end

    it "returns error when session tracking is disabled" do
      ApiAuthenticationGem.configuration.session_tracking_enabled = false
      result = ApiAuthenticationGem::Auth.revoke_session(jti: "any")
      expect(result[:error]).to eq("Session tracking is not enabled")
    end
  end

  # ---------------------------------------------------------------------------
  # revoke_all_sessions
  # ---------------------------------------------------------------------------
  describe ".revoke_all_sessions" do
    it "revokes all active sessions for the user" do
      user = User.find_by(email: email)
      do_login
      do_login

      result = ApiAuthenticationGem::Auth.revoke_all_sessions(user_id: user.id)
      expect(result[:message]).to include("session(s) revoked")

      active = ApiAuthenticationGem::AuthSession.where(user_id: user.id).active
      expect(active.count).to eq(0)
    end

    it "adds all jtis to the revocation blocklist" do
      user = User.find_by(email: email)
      login_r = do_login
      decoded = ApiAuthenticationGem::Auth.decode(login_r[:token])

      ApiAuthenticationGem::Auth.revoke_all_sessions(user_id: user.id)
      expect(ApiAuthenticationGem::RevokedToken.revoked?(decoded["jti"])).to be true
    end

    it "reports 0 revoked when user has no active sessions" do
      user = User.find_by(email: email)
      ApiAuthenticationGem::AuthSession.where(user_id: user.id).update_all(revoked_at: Time.now)

      result = ApiAuthenticationGem::Auth.revoke_all_sessions(user_id: user.id)
      expect(result[:message]).to eq("0 session(s) revoked")
    end

    it "returns error when session tracking is disabled" do
      ApiAuthenticationGem.configuration.session_tracking_enabled = false
      result = ApiAuthenticationGem::Auth.revoke_all_sessions(user_id: 1)
      expect(result[:error]).to eq("Session tracking is not enabled")
    end
  end

  # ---------------------------------------------------------------------------
  # AuthSession model
  # ---------------------------------------------------------------------------
  describe "ApiAuthenticationGem::AuthSession model" do
    let(:user) { User.find_by(email: email) }

    def build_session(overrides = {})
      ApiAuthenticationGem::AuthSession.create!({
        user_id:    user.id,
        jti:        SecureRandom.uuid,
        expires_at: Time.now + 3600
      }.merge(overrides))
    end

    it "#active? is true for a fresh session" do
      expect(build_session.active?).to be true
    end

    it "#active? is false when revoked" do
      s = build_session(revoked_at: Time.now)
      expect(s.active?).to be false
    end

    it "#active? is false when expired" do
      s = build_session(expires_at: Time.now - 1)
      expect(s.active?).to be false
    end

    it "#revoke! sets revoked_at" do
      s = build_session
      s.revoke!
      expect(s.reload.revoked_at).not_to be_nil
    end

    it ".active scope excludes revoked sessions" do
      s = build_session(revoked_at: Time.now)
      expect(ApiAuthenticationGem::AuthSession.active).not_to include(s)
    end
  end
end
