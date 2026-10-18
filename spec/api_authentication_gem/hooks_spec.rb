require "rails_helper"

RSpec.describe "Auth Event Hooks — ApiAuthenticationGem configuration callbacks" do
  before do
    ApiAuthenticationGem.reset_configuration!
    ApiAuthenticationGem.configure do |config|
      config.secret_key = "hooks-test-secret"
      config.user_class = "User"
    end
  end

  let(:email)    { "hooks@example.com" }
  let(:password) { "securepass" }

  # ---------------------------------------------------------------------------
  # on_signup
  # ---------------------------------------------------------------------------
  describe "on_signup hook" do
    it "is called with the created user after a successful signup" do
      received = []
      ApiAuthenticationGem.configuration.on_signup = ->(user) { received << user }

      ApiAuthenticationGem::Auth.signup(email: email, password: password)

      expect(received.length).to eq(1)
      expect(received.first).to be_a(User)
      expect(received.first.email).to eq(email)
    end

    it "is not called when signup fails" do
      call_count = 0
      ApiAuthenticationGem.configuration.on_signup = ->(_user) { call_count += 1 }

      ApiAuthenticationGem::Auth.signup(email: "", password: password)
      expect(call_count).to eq(0)
    end

    it "does not raise or break signup when hook itself raises" do
      ApiAuthenticationGem.configuration.on_signup = ->(_user) { raise "Hook exploded!" }

      result = ApiAuthenticationGem::Auth.signup(email: email, password: password)
      # Auth still succeeds; hook error is swallowed
      expect(result[:token]).to be_a(String)
      expect(result[:error]).to be_nil
    end
  end

  # ---------------------------------------------------------------------------
  # on_login
  # ---------------------------------------------------------------------------
  describe "on_login hook" do
    before { ApiAuthenticationGem::Auth.signup(email: email, password: password) }

    it "is called with the user after a successful login" do
      received = []
      ApiAuthenticationGem.configuration.on_login = ->(user) { received << user }

      ApiAuthenticationGem::Auth.login(email: email, password: password)

      expect(received.length).to eq(1)
      expect(received.first.email).to eq(email)
    end

    it "is not called after a failed login" do
      call_count = 0
      ApiAuthenticationGem.configuration.on_login = ->(_) { call_count += 1 }

      ApiAuthenticationGem::Auth.login(email: email, password: "wrong")
      expect(call_count).to eq(0)
    end

    it "is called after verify_magic_link (magic link login)" do
      ApiAuthenticationGem.configuration.magic_link_enabled = true
      received = []
      ApiAuthenticationGem.configuration.on_login = ->(user) { received << user }

      token = ApiAuthenticationGem::Auth.send_magic_link(email: email)[:magic_token]
      ApiAuthenticationGem::Auth.verify_magic_link(token: token)

      expect(received.length).to eq(1)
    end

    it "does not raise or break login when hook raises" do
      ApiAuthenticationGem.configuration.on_login = ->(_) { raise "Hook exploded!" }

      result = ApiAuthenticationGem::Auth.login(email: email, password: password)
      expect(result[:token]).to be_a(String)
    end
  end

  # ---------------------------------------------------------------------------
  # on_login_failure
  # ---------------------------------------------------------------------------
  describe "on_login_failure hook" do
    before { ApiAuthenticationGem::Auth.signup(email: email, password: password) }

    it "is called with the email after a wrong password" do
      received = []
      ApiAuthenticationGem.configuration.on_login_failure = ->(e) { received << e }

      ApiAuthenticationGem::Auth.login(email: email, password: "wrongpass")

      expect(received).to eq([email])
    end

    it "is called when the email does not exist" do
      received = []
      ApiAuthenticationGem.configuration.on_login_failure = ->(e) { received << e }

      ApiAuthenticationGem::Auth.login(email: "nobody@example.com", password: password)
      expect(received).to eq(["nobody@example.com"])
    end

    it "is not called after a successful login" do
      call_count = 0
      ApiAuthenticationGem.configuration.on_login_failure = ->(_) { call_count += 1 }

      ApiAuthenticationGem::Auth.login(email: email, password: password)
      expect(call_count).to eq(0)
    end
  end

  # ---------------------------------------------------------------------------
  # on_logout
  # ---------------------------------------------------------------------------
  describe "on_logout hook" do
    before do
      ApiAuthenticationGem.configuration.revocation_enabled = true
      ApiAuthenticationGem::Auth.signup(email: email, password: password)
    end

    it "is called with the jti after a successful revocation" do
      token   = ApiAuthenticationGem::Auth.login(email: email, password: password)[:token]
      decoded = ApiAuthenticationGem::Auth.decode(token)
      jti     = decoded["jti"]

      received = []
      ApiAuthenticationGem.configuration.on_logout = ->(j) { received << j }

      ApiAuthenticationGem::Auth.revoke(token: token)
      expect(received).to eq([jti])
    end

    it "is not called when revocation fails (invalid token)" do
      call_count = 0
      ApiAuthenticationGem.configuration.on_logout = ->(_) { call_count += 1 }

      ApiAuthenticationGem::Auth.revoke(token: "invalid.token")
      expect(call_count).to eq(0)
    end
  end

  # ---------------------------------------------------------------------------
  # on_password_reset
  # ---------------------------------------------------------------------------
  describe "on_password_reset hook" do
    before { ApiAuthenticationGem::Auth.signup(email: email, password: password) }

    it "is called with the user after a successful password reset" do
      reset_result = ApiAuthenticationGem::Auth.request_password_reset(email: email)

      received = []
      ApiAuthenticationGem.configuration.on_password_reset = ->(user) { received << user }

      ApiAuthenticationGem::Auth.reset_password(
        reset_token: reset_result[:reset_token], new_password: "newpassword"
      )

      expect(received.length).to eq(1)
      expect(received.first.email).to eq(email)
    end

    it "is not called when the reset token is invalid" do
      call_count = 0
      ApiAuthenticationGem.configuration.on_password_reset = ->(_) { call_count += 1 }

      ApiAuthenticationGem::Auth.reset_password(reset_token: "fake", new_password: "newpassword")
      expect(call_count).to eq(0)
    end
  end

  # ---------------------------------------------------------------------------
  # nil hook (not configured) is silently ignored
  # ---------------------------------------------------------------------------
  describe "nil hooks" do
    it "does not raise when on_signup is nil" do
      ApiAuthenticationGem.configuration.on_signup = nil
      expect {
        ApiAuthenticationGem::Auth.signup(email: email, password: password)
      }.not_to raise_error
    end

    it "does not raise when on_login is nil" do
      ApiAuthenticationGem::Auth.signup(email: email, password: password)
      ApiAuthenticationGem.configuration.on_login = nil
      expect {
        ApiAuthenticationGem::Auth.login(email: email, password: password)
      }.not_to raise_error
    end
  end
end
