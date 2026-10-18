require "rails_helper"

RSpec.describe ApiAuthenticationGem::Auth do
  before do
    ApiAuthenticationGem.reset_configuration!
    ApiAuthenticationGem.configure do |config|
      config.secret_key = "test-secret-key-for-specs"
      config.user_class = "User"
      # Tier 1 features off by default — individual specs opt-in via configure
    end
  end

  let(:email)    { "test@example.com" }
  let(:password) { "securepass" }

  # ---------------------------------------------------------------------------
  # signup
  # ---------------------------------------------------------------------------
  describe ".signup" do
    context "with valid credentials" do
      it "returns message, user, and access token" do
        result = described_class.signup(email: email, password: password)

        expect(result[:error]).to be_nil
        expect(result[:message]).to eq("User created successfully")
        expect(result[:user]).to be_a(User)
        expect(result[:user].email).to eq(email)
        expect(result[:token]).to be_a(String)
      end

      it "does not return a refresh_token when refresh_tokens_enabled is false" do
        result = described_class.signup(email: email, password: password)
        expect(result[:refresh_token]).to be_nil
      end

      it "returns a refresh_token when refresh_tokens_enabled is true" do
        ApiAuthenticationGem.configuration.refresh_tokens_enabled = true
        result = described_class.signup(email: email, password: password)
        expect(result[:refresh_token]).to be_a(String)
      end

      it "downcases and strips the email" do
        result = described_class.signup(email: "  TEST@Example.COM  ", password: password)
        expect(result[:user].email).to eq("test@example.com")
      end
    end

    context "with missing email" do
      it "returns an error" do
        result = described_class.signup(email: "", password: password)
        expect(result[:error]).to eq("Email is required")
      end
    end

    context "with a password that is too short" do
      it "returns an error" do
        result = described_class.signup(email: email, password: "abc")
        expect(result[:error]).to include("at least")
      end
    end

    context "with a duplicate email" do
      it "returns an error instead of raising" do
        described_class.signup(email: email, password: password)
        result = described_class.signup(email: email, password: password)
        expect(result[:error]).to be_present
        expect(result[:user]).to be_nil
      end
    end
  end

  # ---------------------------------------------------------------------------
  # login
  # ---------------------------------------------------------------------------
  describe ".login" do
    before { described_class.signup(email: email, password: password) }

    context "with valid credentials" do
      it "returns access token and user" do
        result = described_class.login(email: email, password: password)

        expect(result[:error]).to be_nil
        expect(result[:token]).to be_a(String)
        expect(result[:user].email).to eq(email)
      end

      it "does not return refresh_token when disabled" do
        result = described_class.login(email: email, password: password)
        expect(result[:refresh_token]).to be_nil
      end

      it "returns refresh_token when enabled" do
        ApiAuthenticationGem.configuration.refresh_tokens_enabled = true
        result = described_class.login(email: email, password: password)
        expect(result[:refresh_token]).to be_a(String)
      end
    end

    context "with wrong password" do
      it "returns an error hash, not nil" do
        result = described_class.login(email: email, password: "wrongpass")
        expect(result[:error]).to eq("Invalid email or password")
        expect(result[:token]).to be_nil
      end
    end

    context "with unknown email" do
      it "returns an error hash" do
        result = described_class.login(email: "nobody@example.com", password: password)
        expect(result[:error]).to eq("Invalid email or password")
      end
    end

    context "with blank fields" do
      it "returns error for blank email" do
        result = described_class.login(email: "", password: password)
        expect(result[:error]).to be_present
      end

      it "returns error for blank password" do
        result = described_class.login(email: email, password: "")
        expect(result[:error]).to be_present
      end
    end
  end

  # ---------------------------------------------------------------------------
  # decode
  # ---------------------------------------------------------------------------
  describe ".decode" do
    it "decodes a valid token and returns user id in sub" do
      result  = described_class.signup(email: email, password: password)
      decoded = described_class.decode(result[:token])
      expect(decoded["sub"]).to eq(result[:user].id)
    end

    it "returns nil for an invalid token" do
      expect(described_class.decode("bad.token.here")).to be_nil
    end

    it "returns nil for a nil token" do
      expect(described_class.decode(nil)).to be_nil
    end

    it "returns nil for an expired token" do
      ApiAuthenticationGem.configuration.token_expiry = -10
      result  = described_class.signup(email: email, password: password)
      decoded = described_class.decode(result[:token])
      expect(decoded).to be_nil
    end
  end
end
