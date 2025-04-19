require "rails_helper"

RSpec.describe ApiAuthenticationGem::Configuration do
  it "uses default values" do
    config = ApiAuthenticationGem::Configuration.new
    expect(config.secret_key).to be_a(String)
    expect(config.user_class).to eq("User")
  end

  it "allows custom configuration" do
    ApiAuthenticationGem.configure do |config|
      config.secret_key = "custom123"
      config.user_class = "Admin"
    end

    config = ApiAuthenticationGem.configuration
    expect(config.secret_key).to eq("custom123")
    expect(config.user_class).to eq("Admin")
  end
end
