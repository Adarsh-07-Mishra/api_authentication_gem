require "rails_helper"
require "openssl"

RSpec.describe "RS256 Algorithm — ApiAuthenticationGem asymmetric JWT" do
  # Generate the key pair once per example group (2048-bit is slower, done once)
  let(:rsa_key)     { OpenSSL::PKey::RSA.generate(2048) }
  let(:private_key) { rsa_key }
  let(:public_key)  { rsa_key.public_key }

  before do
    ApiAuthenticationGem.reset_configuration!
    ApiAuthenticationGem.configure do |config|
      config.algorithm   = "RS256"
      config.private_key = private_key
      config.public_key  = public_key
      config.user_class  = "User"
    end
  end

  let(:email)    { "rs256@example.com" }
  let(:password) { "securepass" }

  # ---------------------------------------------------------------------------
  # signup / login issue RS256 tokens
  # ---------------------------------------------------------------------------
  describe "signup with RS256" do
    it "returns a valid RS256-signed token" do
      result = ApiAuthenticationGem::Auth.signup(email: email, password: password)

      expect(result[:error]).to be_nil
      expect(result[:token]).to be_a(String)
    end

    it "token can be decoded and verified with the public key only" do
      result  = ApiAuthenticationGem::Auth.signup(email: email, password: password)
      decoded = JWT.decode(result[:token], public_key, true, algorithm: "RS256").first

      expect(decoded["sub"]).to eq(result[:user].id)
    end

    it "token cannot be verified with a different public key" do
      result       = ApiAuthenticationGem::Auth.signup(email: email, password: password)
      other_key    = OpenSSL::PKey::RSA.generate(2048).public_key

      expect {
        JWT.decode(result[:token], other_key, true, algorithm: "RS256")
      }.to raise_error(JWT::VerificationError)
    end

    it "token cannot be decoded as HS256" do
      result = ApiAuthenticationGem::Auth.signup(email: email, password: password)
      expect {
        JWT.decode(result[:token], "any-secret", true, algorithm: "HS256")
      }.to raise_error(JWT::IncorrectAlgorithm)
    end
  end

  describe "login with RS256" do
    before { ApiAuthenticationGem::Auth.signup(email: email, password: password) }

    it "returns a valid RS256-signed token" do
      result = ApiAuthenticationGem::Auth.login(email: email, password: password)
      expect(result[:token]).to be_a(String)
      expect(result[:error]).to be_nil
    end

    it "decode returns the correct payload" do
      result  = ApiAuthenticationGem::Auth.login(email: email, password: password)
      decoded = ApiAuthenticationGem::Auth.decode(result[:token])

      expect(decoded["sub"]).to eq(result[:user].id)
      expect(decoded["jti"]).to be_a(String)
    end
  end

  # ---------------------------------------------------------------------------
  # Auth.decode with RS256
  # ---------------------------------------------------------------------------
  describe ".decode with RS256" do
    before { ApiAuthenticationGem::Auth.signup(email: email, password: password) }

    it "returns the payload for a valid RS256 token" do
      token   = ApiAuthenticationGem::Auth.login(email: email, password: password)[:token]
      decoded = ApiAuthenticationGem::Auth.decode(token)

      expect(decoded).not_to be_nil
      expect(decoded["sub"]).to be_a(Integer)
    end

    it "returns nil for an HS256 token when configured for RS256" do
      hs256_token = JWT.encode({ sub: 1, jti: "x", exp: Time.now.to_i + 3600 },
                               "some-secret", "HS256")
      expect(ApiAuthenticationGem::Auth.decode(hs256_token)).to be_nil
    end

    it "returns nil for an expired RS256 token" do
      ApiAuthenticationGem.configuration.token_expiry = -10
      token = ApiAuthenticationGem::Auth.login(email: email, password: password)[:token]
      expect(ApiAuthenticationGem::Auth.decode(token)).to be_nil
    end

    it "returns nil for a tampered token" do
      token  = ApiAuthenticationGem::Auth.login(email: email, password: password)[:token]
      parts  = token.split(".")
      parts[1] = Base64.urlsafe_encode64('{"sub":9999,"exp":9999999999}', padding: false)
      expect(ApiAuthenticationGem::Auth.decode(parts.join("."))).to be_nil
    end
  end

  # ---------------------------------------------------------------------------
  # Configuration validation for RS256
  # ---------------------------------------------------------------------------
  describe "Configuration validation for RS256" do
    it "raises ConfigurationError when private_key is nil" do
      expect {
        ApiAuthenticationGem.reset_configuration!
        ApiAuthenticationGem.configure do |config|
          config.algorithm   = "RS256"
          config.private_key = nil
          config.public_key  = public_key
        end
      }.to raise_error(ApiAuthenticationGem::ConfigurationError, /private_key/)
    end

    it "raises ConfigurationError when public_key is nil" do
      expect {
        ApiAuthenticationGem.reset_configuration!
        ApiAuthenticationGem.configure do |config|
          config.algorithm   = "RS256"
          config.private_key = private_key
          config.public_key  = nil
        end
      }.to raise_error(ApiAuthenticationGem::ConfigurationError, /public_key/)
    end

    it "raises ConfigurationError for an unknown algorithm" do
      expect {
        ApiAuthenticationGem.reset_configuration!
        ApiAuthenticationGem.configure do |config|
          config.algorithm  = "ES256"
          config.secret_key = "x"
        end
      }.to raise_error(ApiAuthenticationGem::ConfigurationError, /algorithm/)
    end

    it "allows switching from RS256 back to HS256 without error" do
      expect {
        ApiAuthenticationGem.reset_configuration!
        ApiAuthenticationGem.configure do |config|
          config.algorithm  = "HS256"
          config.secret_key = "hs256-secret"
        end
      }.not_to raise_error
    end
  end

  # ---------------------------------------------------------------------------
  # Revocation works with RS256
  # ---------------------------------------------------------------------------
  describe "revocation with RS256" do
    before do
      ApiAuthenticationGem.configuration.revocation_enabled = true
      ApiAuthenticationGem::Auth.signup(email: email, password: password)
    end

    it "revoke + decode returns nil" do
      token = ApiAuthenticationGem::Auth.login(email: email, password: password)[:token]
      ApiAuthenticationGem::Auth.revoke(token: token)
      expect(ApiAuthenticationGem::Auth.decode(token)).to be_nil
    end
  end
end
