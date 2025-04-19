require "rails_helper"

RSpec.describe ApiAuthenticationGem::Auth do
  before do
    ApiAuthenticationGem.configure do |config|
      config.secret_key = "test-secret"
      config.user_class = "User"
    end
  end

  let(:email) { "test@example.com" }
  let(:password) { "securepass" }

  describe ".signup" do
    it "creates a user and returns token" do
      result = described_class.signup(email: email, password: password)

      expect(result[:user]).to be_a(User)
      expect(result[:user].email).to eq(email)
      expect(result[:token]).to be_a(String)
    end
  end

  describe ".login" do
    before { described_class.signup(email: email, password: password) }

    it "returns token and user for valid login" do
      result = described_class.login(email: email, password: password)
      expect(result[:token]).to be_present
      expect(result[:user].email).to eq(email)
    end

    it "returns nil for invalid login" do
      result = described_class.login(email: email, password: "wrong")
      expect(result).to be_nil
    end
  end

  describe ".decode" do
    it "decodes a valid token" do
      result = described_class.signup(email: email, password: password)
      decoded = described_class.decode(result[:token])
      expect(decoded["user_id"]).to eq(result[:user].id)
    end

    it "returns nil for invalid token" do
      expect(described_class.decode("bad.token")).to be_nil
    end
  end
end
