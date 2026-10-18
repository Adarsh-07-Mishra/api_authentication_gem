require "rails_helper"

RSpec.describe "Refresh Token — ApiAuthenticationGem::Auth.refresh" do
  before do
    ApiAuthenticationGem.reset_configuration!
    ApiAuthenticationGem.configure do |config|
      config.secret_key               = "test-secret-for-refresh"
      config.user_class               = "User"
      config.refresh_tokens_enabled   = true
      config.refresh_token_expiry     = 30 * 24 * 60 * 60 # 30 days
    end
    ApiAuthenticationGem::Auth.signup(email: email, password: password)
  end

  let(:email)    { "refresh@example.com" }
  let(:password) { "securepass" }

  def do_login
    ApiAuthenticationGem::Auth.login(email: email, password: password)
  end

  # ---------------------------------------------------------------------------
  # login integration
  # ---------------------------------------------------------------------------
  describe "login returns both tokens when refresh is enabled" do
    it "includes refresh_token in login response" do
      result = do_login
      expect(result[:token]).to be_a(String)
      expect(result[:refresh_token]).to be_a(String)
    end

    it "stores the refresh token record in DB" do
      result = do_login
      record = ApiAuthenticationGem::RefreshToken.find_by(token: result[:refresh_token])
      expect(record).not_to be_nil
      expect(record.user_id).to eq(result[:user].id)
      expect(record.expires_at).to be > Time.now
      expect(record.revoked_at).to be_nil
    end

    it "each login creates a separate refresh token" do
      r1 = do_login
      r2 = do_login
      expect(r1[:refresh_token]).not_to eq(r2[:refresh_token])
    end
  end

  # ---------------------------------------------------------------------------
  # Auth.refresh — happy path
  # ---------------------------------------------------------------------------
  describe ".refresh — valid token" do
    it "returns a new access token and a new refresh token" do
      login_result   = do_login
      refresh_result = ApiAuthenticationGem::Auth.refresh(
        refresh_token: login_result[:refresh_token]
      )

      expect(refresh_result[:error]).to be_nil
      expect(refresh_result[:token]).to be_a(String)
      expect(refresh_result[:refresh_token]).to be_a(String)
      expect(refresh_result[:user].email).to eq(email)
    end

    it "issues a different access token each time" do
      login_result = do_login
      r1 = ApiAuthenticationGem::Auth.refresh(refresh_token: login_result[:refresh_token])
      r2 = ApiAuthenticationGem::Auth.refresh(refresh_token: r1[:refresh_token])
      expect(r1[:token]).not_to eq(r2[:token])
    end

    it "the new access token decodes correctly" do
      login_result   = do_login
      refresh_result = ApiAuthenticationGem::Auth.refresh(
        refresh_token: login_result[:refresh_token]
      )
      decoded = ApiAuthenticationGem::Auth.decode(refresh_result[:token])
      expect(decoded["sub"]).to eq(refresh_result[:user].id)
    end
  end

  # ---------------------------------------------------------------------------
  # Auth.refresh — token rotation (old token is revoked)
  # ---------------------------------------------------------------------------
  describe ".refresh — token rotation" do
    it "revokes the old refresh token after use" do
      login_result = do_login
      old_token    = login_result[:refresh_token]

      ApiAuthenticationGem::Auth.refresh(refresh_token: old_token)

      record = ApiAuthenticationGem::RefreshToken.find_by(token: old_token)
      expect(record.revoked_at).not_to be_nil
    end

    it "reusing the old refresh token returns an error" do
      login_result = do_login
      old_token    = login_result[:refresh_token]

      ApiAuthenticationGem::Auth.refresh(refresh_token: old_token)

      result = ApiAuthenticationGem::Auth.refresh(refresh_token: old_token)
      expect(result[:error]).to eq("Refresh token has been revoked")
    end
  end

  # ---------------------------------------------------------------------------
  # Auth.refresh — failure cases
  # ---------------------------------------------------------------------------
  describe ".refresh — failure cases" do
    it "returns error for a nil token" do
      result = ApiAuthenticationGem::Auth.refresh(refresh_token: nil)
      expect(result[:error]).to be_present
    end

    it "returns error for a blank token" do
      result = ApiAuthenticationGem::Auth.refresh(refresh_token: "   ")
      expect(result[:error]).to be_present
    end

    it "returns error for a non-existent token string" do
      result = ApiAuthenticationGem::Auth.refresh(refresh_token: "completely-fake-token")
      expect(result[:error]).to eq("Invalid refresh token")
    end

    it "returns error for an expired refresh token" do
      login_result = do_login
      token_str    = login_result[:refresh_token]

      # Force-expire the DB record
      ApiAuthenticationGem::RefreshToken
        .find_by(token: token_str)
        .update!(expires_at: Time.now - 1)

      result = ApiAuthenticationGem::Auth.refresh(refresh_token: token_str)
      expect(result[:error]).to eq("Refresh token has expired")
    end

    it "returns error when refresh_tokens_enabled is false" do
      ApiAuthenticationGem.configuration.refresh_tokens_enabled = false
      result = ApiAuthenticationGem::Auth.refresh(refresh_token: "any-token")
      expect(result[:error]).to eq("Refresh tokens are not enabled")
    end
  end

  # ---------------------------------------------------------------------------
  # RefreshToken model
  # ---------------------------------------------------------------------------
  describe "ApiAuthenticationGem::RefreshToken model" do
    let(:user) { User.create!(email: "model-test@example.com", password: password) }

    it "#active? returns true for a valid token" do
      rt = ApiAuthenticationGem::RefreshToken.create!(
        user_id:    user.id,
        token:      "abc123",
        expires_at: Time.now + 3600
      )
      expect(rt.active?).to be true
    end

    it "#active? returns false for a revoked token" do
      rt = ApiAuthenticationGem::RefreshToken.create!(
        user_id:    user.id,
        token:      "def456",
        expires_at: Time.now + 3600,
        revoked_at: Time.now
      )
      expect(rt.active?).to be false
    end

    it "#active? returns false for an expired token" do
      rt = ApiAuthenticationGem::RefreshToken.create!(
        user_id:    user.id,
        token:      "ghi789",
        expires_at: Time.now - 1
      )
      expect(rt.active?).to be false
    end

    it "#revoke! sets revoked_at" do
      rt = ApiAuthenticationGem::RefreshToken.create!(
        user_id:    user.id,
        token:      "jkl000",
        expires_at: Time.now + 3600
      )
      rt.revoke!
      expect(rt.reload.revoked_at).not_to be_nil
    end
  end
end
