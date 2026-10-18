require "rails_helper"

RSpec.describe ApiAuthenticationGem::Configuration do
  before { ApiAuthenticationGem.reset_configuration! }

  # ---------------------------------------------------------------------------
  # defaults
  # ---------------------------------------------------------------------------
  describe "defaults" do
    subject(:config) { described_class.new }

    it "defaults user_class to 'User'"               do expect(config.user_class).to eq("User") end
    it "defaults email_attribute to :email"           do expect(config.email_attribute).to eq(:email) end
    it "defaults password_attribute to :password"     do expect(config.password_attribute).to eq(:password) end
    it "defaults identifier to :email"                do expect(config.identifier).to eq(:email) end
    it "defaults password_verify_method to :authenticate" do
      expect(config.password_verify_method).to eq(:authenticate)
    end
    it "defaults token_expiry to 24 hours"   do expect(config.token_expiry).to eq(24 * 60 * 60) end
    it "defaults min_password_length to 6"   do expect(config.min_password_length).to eq(6) end
  end

  # ---------------------------------------------------------------------------
  # configure block
  # ---------------------------------------------------------------------------
  describe "ApiAuthenticationGem.configure" do
    it "applies custom values and passes validate!" do
      ApiAuthenticationGem.configure do |config|
        config.secret_key          = "my-secret-key"
        config.user_class          = "Admin"
        config.token_expiry        = 3600
        config.min_password_length = 8
      end

      config = ApiAuthenticationGem.configuration
      expect(config.secret_key).to eq("my-secret-key")
      expect(config.user_class).to eq("Admin")
      expect(config.token_expiry).to eq(3600)
      expect(config.min_password_length).to eq(8)
    end
  end

  # ---------------------------------------------------------------------------
  # validate!
  # ---------------------------------------------------------------------------
  describe "#validate!" do
    it "raises ConfigurationError when secret_key is nil" do
      config = described_class.new
      config.secret_key = nil
      expect { config.validate! }
        .to raise_error(ApiAuthenticationGem::ConfigurationError, /secret_key/)
    end

    it "raises ConfigurationError when secret_key is blank" do
      config = described_class.new
      config.secret_key = "   "
      expect { config.validate! }
        .to raise_error(ApiAuthenticationGem::ConfigurationError, /secret_key/)
    end

    it "raises ConfigurationError when token_expiry is zero" do
      config = described_class.new
      config.secret_key  = "valid-key"
      config.token_expiry = 0
      expect { config.validate! }
        .to raise_error(ApiAuthenticationGem::ConfigurationError, /token_expiry/)
    end

    it "raises ConfigurationError when token_expiry is negative" do
      config = described_class.new
      config.secret_key   = "valid-key"
      config.token_expiry = -1
      expect { config.validate! }
        .to raise_error(ApiAuthenticationGem::ConfigurationError, /token_expiry/)
    end

    it "raises ConfigurationError when min_password_length is zero" do
      config = described_class.new
      config.secret_key          = "valid-key"
      config.min_password_length = 0
      expect { config.validate! }
        .to raise_error(ApiAuthenticationGem::ConfigurationError, /min_password_length/)
    end

    it "does not raise when all values are valid" do
      config = described_class.new
      config.secret_key = "valid-key"
      expect { config.validate! }.not_to raise_error
    end
  end
end
