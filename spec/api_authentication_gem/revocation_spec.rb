require "rails_helper"

RSpec.describe "Token Revocation — ApiAuthenticationGem::Auth.revoke" do
  before do
    ApiAuthenticationGem.reset_configuration!
    ApiAuthenticationGem.configure do |config|
      config.secret_key          = "test-secret-for-revocation"
      config.user_class          = "User"
      config.revocation_enabled  = true
    end
    ApiAuthenticationGem::Auth.signup(email: email, password: password)
  end

  let(:email)    { "revoke@example.com" }
  let(:password) { "securepass" }

  def issue_token
    ApiAuthenticationGem::Auth.login(email: email, password: password)[:token]
  end

  # ---------------------------------------------------------------------------
  # Auth.revoke — happy path
  # ---------------------------------------------------------------------------
  describe ".revoke — success" do
    it "returns a success message" do
      result = ApiAuthenticationGem::Auth.revoke(token: issue_token)
      expect(result[:message]).to eq("Token revoked successfully")
      expect(result[:error]).to be_nil
    end

    it "stores the jti in the revoked_tokens table" do
      token   = issue_token
      decoded = JWT.decode(token, "test-secret-for-revocation", true, algorithm: "HS256").first
      jti     = decoded["jti"]

      ApiAuthenticationGem::Auth.revoke(token: token)

      expect(ApiAuthenticationGem::RevokedToken.where(jti: jti).exists?).to be true
    end
  end

  # ---------------------------------------------------------------------------
  # Auth.decode — honours revocation
  # ---------------------------------------------------------------------------
  describe ".decode — after revocation" do
    it "returns nil for a revoked token" do
      token = issue_token
      ApiAuthenticationGem::Auth.revoke(token: token)
      expect(ApiAuthenticationGem::Auth.decode(token)).to be_nil
    end

    it "still decodes a non-revoked token normally" do
      t1 = issue_token
      t2 = issue_token # separate token, separate jti
      ApiAuthenticationGem::Auth.revoke(token: t1)

      decoded = ApiAuthenticationGem::Auth.decode(t2)
      expect(decoded).not_to be_nil
      expect(decoded["sub"]).to be_present
    end

    it "does not check revocation when revocation_enabled is false" do
      token = issue_token
      decoded_before = JWT.decode(token, "test-secret-for-revocation", true, algorithm: "HS256").first

      ApiAuthenticationGem.configuration.revocation_enabled = false

      # Even if we manually add it to the blocklist, decode ignores the table
      ApiAuthenticationGem::RevokedToken.create!(
        jti:        decoded_before["jti"],
        expires_at: Time.at(decoded_before["exp"])
      )

      expect(ApiAuthenticationGem::Auth.decode(token)).not_to be_nil
    end
  end

  # ---------------------------------------------------------------------------
  # Auth.revoke — failure cases
  # ---------------------------------------------------------------------------
  describe ".revoke — failure cases" do
    it "returns error for nil token" do
      result = ApiAuthenticationGem::Auth.revoke(token: nil)
      expect(result[:error]).to be_present
    end

    it "returns error for blank token" do
      result = ApiAuthenticationGem::Auth.revoke(token: "")
      expect(result[:error]).to be_present
    end

    it "returns error for a tampered / invalid token" do
      result = ApiAuthenticationGem::Auth.revoke(token: "invalid.jwt.token")
      expect(result[:error]).to eq("Invalid token")
    end

    it "returns error for an already-expired token" do
      ApiAuthenticationGem.configuration.token_expiry = -10
      expired_token = ApiAuthenticationGem::Auth.login(
        email: email, password: password
      )[:token]

      result = ApiAuthenticationGem::Auth.revoke(token: expired_token)
      expect(result[:error]).to eq("Cannot revoke an already-expired token")
    end

    it "returns error when revocation is not enabled" do
      ApiAuthenticationGem.configuration.revocation_enabled = false
      result = ApiAuthenticationGem::Auth.revoke(token: issue_token)
      expect(result[:error]).to eq("Token revocation is not enabled")
    end

    it "handles revoking the same token twice gracefully" do
      token = issue_token
      ApiAuthenticationGem::Auth.revoke(token: token)
      result = ApiAuthenticationGem::Auth.revoke(token: token)
      # find_or_create_by! is idempotent — no error
      expect(result[:error]).to be_nil
      expect(result[:message]).to eq("Token revoked successfully")
    end
  end

  # ---------------------------------------------------------------------------
  # RevokedToken model
  # ---------------------------------------------------------------------------
  describe "ApiAuthenticationGem::RevokedToken model" do
    it ".revoked? returns true for a stored jti" do
      ApiAuthenticationGem::RevokedToken.create!(jti: "abc-uuid", expires_at: Time.now + 3600)
      expect(ApiAuthenticationGem::RevokedToken.revoked?("abc-uuid")).to be true
    end

    it ".revoked? returns false for an unknown jti" do
      expect(ApiAuthenticationGem::RevokedToken.revoked?("unknown-jti")).to be false
    end

    it ".revoked? returns false for a nil jti" do
      expect(ApiAuthenticationGem::RevokedToken.revoked?(nil)).to be false
    end

    it ".cleanup! removes expired entries" do
      ApiAuthenticationGem::RevokedToken.create!(jti: "old", expires_at: Time.now - 1)
      ApiAuthenticationGem::RevokedToken.create!(jti: "new", expires_at: Time.now + 3600)
      ApiAuthenticationGem::RevokedToken.cleanup!
      expect(ApiAuthenticationGem::RevokedToken.where(jti: "old").exists?).to be false
      expect(ApiAuthenticationGem::RevokedToken.where(jti: "new").exists?).to be true
    end
  end
end
