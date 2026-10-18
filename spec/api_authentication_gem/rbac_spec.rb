require "rails_helper"

# Minimal controller double that includes the concern so we can unit-test
# authorize_role! without a full Rails request stack.
class TestController
  include ApiAuthenticationGem::Concerns::Authenticatable

  attr_reader :rendered_json, :rendered_status

  def request
    @request ||= Struct.new(:headers).new("Authorization" => nil)
  end

  def render(json: nil, status: nil)
    @rendered_json   = json
    @rendered_status = status
  end

  def set_current_user(user)
    @current_user = user
  end
end

RSpec.describe "RBAC — ApiAuthenticationGem::Concerns::Authenticatable#authorize_role!" do
  before do
    ApiAuthenticationGem.reset_configuration!
    ApiAuthenticationGem.configure do |config|
      config.secret_key      = "rbac-test-secret"
      config.user_class      = "User"
      config.role_attribute  = :role
    end
  end

  let(:password)   { "securepass" }
  let(:admin_user) { User.create!(email: "admin@example.com", password: password, role: "admin") }
  let(:mod_user)   { User.create!(email: "mod@example.com",   password: password, role: "moderator") }
  let(:plain_user) { User.create!(email: "user@example.com",  password: password, role: "user") }
  let(:controller) { TestController.new }

  # ---------------------------------------------------------------------------
  # Access granted
  # ---------------------------------------------------------------------------
  describe "access granted" do
    it "returns true when user has the required role" do
      controller.set_current_user(admin_user)
      result = controller.authorize_role!(:admin)
      expect(result).to be true
      expect(controller.rendered_status).to be_nil
    end

    it "returns true when user role matches one of several allowed roles" do
      controller.set_current_user(mod_user)
      result = controller.authorize_role!(:admin, :moderator)
      expect(result).to be true
    end

    it "accepts role as string or symbol" do
      controller.set_current_user(admin_user)
      expect(controller.authorize_role!("admin")).to be true
    end

    it "allows any role when no roles are specified (empty list)" do
      controller.set_current_user(plain_user)
      result = controller.authorize_role!("user")
      expect(result).to be true
    end
  end

  # ---------------------------------------------------------------------------
  # Access denied
  # ---------------------------------------------------------------------------
  describe "access denied" do
    it "renders 403 when role does not match" do
      controller.set_current_user(plain_user)
      result = controller.authorize_role!(:admin)

      expect(result).to be false
      expect(controller.rendered_status).to eq(:forbidden)
      expect(controller.rendered_json[:error]).to include("Forbidden")
    end

    it "includes required and current role in the 403 response" do
      controller.set_current_user(plain_user)
      controller.authorize_role!(:admin, :moderator)

      expect(controller.rendered_json[:required]).to eq(["admin", "moderator"])
      expect(controller.rendered_json[:current]).to eq("user")
    end

    it "renders 401 when current_user is nil (not authenticated)" do
      result = controller.authorize_role!(:admin)

      expect(result).to be false
      expect(controller.rendered_status).to eq(:unauthorized)
    end
  end

  # ---------------------------------------------------------------------------
  # Custom role_attribute
  # ---------------------------------------------------------------------------
  describe "custom role_attribute" do
    before { ApiAuthenticationGem.configuration.role_attribute = :role }

    it "reads the configured column" do
      user = User.create!(email: "custom@example.com", password: password, role: "superadmin")
      controller.set_current_user(user)
      expect(controller.authorize_role!(:superadmin)).to be true
    end
  end

  # ---------------------------------------------------------------------------
  # Real auth flow integration
  # ---------------------------------------------------------------------------
  describe "integration: token → current_user → authorize_role!" do
    it "returns the correct role for the logged-in user" do
      ApiAuthenticationGem::Auth.signup(
        email: "integ@example.com", password: password
      )
      user = User.find_by(email: "integ@example.com")
      user.update!(role: "admin")

      result = ApiAuthenticationGem::Auth.login(
        email: "integ@example.com", password: password
      )
      decoded = ApiAuthenticationGem::Auth.decode(result[:token])

      logged_in_user = User.find_by(id: decoded["sub"])
      controller.set_current_user(logged_in_user)

      expect(controller.authorize_role!(:admin)).to be true
      expect(controller.authorize_role!(:user)).to  be false
    end
  end
end
