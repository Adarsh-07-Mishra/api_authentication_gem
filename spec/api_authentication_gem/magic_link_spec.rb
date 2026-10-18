require "rails_helper"

RSpec.describe "Magic Link — ApiAuthenticationGem::Auth magic link flow" do
  before do
    ApiAuthenticationGem.reset_configuration!
    ApiAuthenticationGem.configure do |config|
      config.secret_key          = "magic-link-test-secret"
      config.user_class          = "User"
      config.magic_link_enabled  = true
      config.magic_link_expiry   = 15 * 60
    end
    ApiAuthenticationGem::Auth.signup(email: email, password: password)
  end

  let(:email)    { "magic@example.com" }
  let(:password) { "securepass" }

  # ---------------------------------------------------------------------------
  # send_magic_link
  # ---------------------------------------------------------------------------
  describe ".send_magic_link" do
    context "with a registered email" do
      it "returns the standard message and a magic_token" do
        result = ApiAuthenticationGem::Auth.send_magic_link(email: email)

        expect(result[:error]).to be_nil
        expect(result[:message]).to eq("If that email is registered, a magic link has been sent.")
        expect(result[:magic_token]).to be_a(String)
        expect(result[:magic_token].length).to be >= 20
      end

      it "stores a MagicLink record in the DB" do
        result = ApiAuthenticationGem::Auth.send_magic_link(email: email)
        record = ApiAuthenticationGem::MagicLink.find_by(token: result[:magic_token])

        expect(record).not_to be_nil
        expect(record.identifier).to eq(email)
        expect(record.used_at).to be_nil
        expect(record.expires_at).to be > Time.now
      end

      it "invalidates the previous magic link when a new one is requested" do
        r1 = ApiAuthenticationGem::Auth.send_magic_link(email: email)
        r2 = ApiAuthenticationGem::Auth.send_magic_link(email: email)

        old = ApiAuthenticationGem::MagicLink.find_by(token: r1[:magic_token])
        expect(old.used?).to be true

        fresh = ApiAuthenticationGem::MagicLink.find_by(token: r2[:magic_token])
        expect(fresh.used?).to be false
      end

      it "each request generates a unique token" do
        r1 = ApiAuthenticationGem::Auth.send_magic_link(email: email)
        ApiAuthenticationGem::MagicLink.find_by(token: r1[:magic_token]).consume!
        r2 = ApiAuthenticationGem::Auth.send_magic_link(email: email)
        expect(r1[:magic_token]).not_to eq(r2[:magic_token])
      end
    end

    context "with an unregistered email" do
      it "returns the same message with no magic_token (no enumeration)" do
        result = ApiAuthenticationGem::Auth.send_magic_link(email: "ghost@example.com")

        expect(result[:message]).to eq("If that email is registered, a magic link has been sent.")
        expect(result[:magic_token]).to be_nil
        expect(result[:error]).to be_nil
      end
    end

    context "with a blank email" do
      it "returns an error" do
        result = ApiAuthenticationGem::Auth.send_magic_link(email: "")
        expect(result[:error]).to eq("Email is required")
      end
    end

    context "when magic_link_enabled is false" do
      it "returns an error" do
        ApiAuthenticationGem.configuration.magic_link_enabled = false
        result = ApiAuthenticationGem::Auth.send_magic_link(email: email)
        expect(result[:error]).to eq("Magic link login is not enabled")
      end
    end
  end

  # ---------------------------------------------------------------------------
  # verify_magic_link
  # ---------------------------------------------------------------------------
  describe ".verify_magic_link" do
    def get_magic_token
      ApiAuthenticationGem::Auth.send_magic_link(email: email)[:magic_token]
    end

    context "with a valid token" do
      it "returns a JWT access token and the user" do
        token  = get_magic_token
        result = ApiAuthenticationGem::Auth.verify_magic_link(token: token)

        expect(result[:error]).to be_nil
        expect(result[:token]).to be_a(String)
        expect(result[:user].email).to eq(email)
      end

      it "the access token decodes to the correct user" do
        token  = get_magic_token
        result = ApiAuthenticationGem::Auth.verify_magic_link(token: token)

        decoded = ApiAuthenticationGem::Auth.decode(result[:token])
        expect(decoded["sub"]).to eq(result[:user].id)
      end

      it "marks the magic link as used" do
        token = get_magic_token
        ApiAuthenticationGem::Auth.verify_magic_link(token: token)

        record = ApiAuthenticationGem::MagicLink.find_by(token: token)
        expect(record.used?).to be true
      end

      it "returns refresh_token when refresh_tokens_enabled" do
        ApiAuthenticationGem.configuration.refresh_tokens_enabled = true
        token  = get_magic_token
        result = ApiAuthenticationGem::Auth.verify_magic_link(token: token)
        expect(result[:refresh_token]).to be_a(String)
      end
    end

    context "with an already-used token" do
      it "returns an error" do
        token = get_magic_token
        ApiAuthenticationGem::Auth.verify_magic_link(token: token)

        result = ApiAuthenticationGem::Auth.verify_magic_link(token: token)
        expect(result[:error]).to eq("Invalid or expired magic link")
      end
    end

    context "with an expired token" do
      it "returns an error" do
        token = get_magic_token
        ApiAuthenticationGem::MagicLink.find_by(token: token).update!(expires_at: Time.now - 1)

        result = ApiAuthenticationGem::Auth.verify_magic_link(token: token)
        expect(result[:error]).to eq("Invalid or expired magic link")
      end
    end

    context "with a blank token" do
      it "returns an error" do
        result = ApiAuthenticationGem::Auth.verify_magic_link(token: "")
        expect(result[:error]).to eq("Magic link token is required")
      end
    end

    context "with a fake token" do
      it "returns an error" do
        result = ApiAuthenticationGem::Auth.verify_magic_link(token: "totally-fake")
        expect(result[:error]).to eq("Invalid or expired magic link")
      end
    end

    context "when magic_link_enabled is false" do
      it "returns an error" do
        ApiAuthenticationGem.configuration.magic_link_enabled = false
        result = ApiAuthenticationGem::Auth.verify_magic_link(token: "any")
        expect(result[:error]).to eq("Magic link login is not enabled")
      end
    end
  end

  # ---------------------------------------------------------------------------
  # MagicLink model
  # ---------------------------------------------------------------------------
  describe "ApiAuthenticationGem::MagicLink model" do
    it "#used? returns false for a fresh link" do
      ml = ApiAuthenticationGem::MagicLink.create!(
        identifier: email, token: "t1", expires_at: Time.now + 900
      )
      expect(ml.used?).to be false
    end

    it "#used? returns true after consume!" do
      ml = ApiAuthenticationGem::MagicLink.create!(
        identifier: email, token: "t2", expires_at: Time.now + 900
      )
      ml.consume!
      expect(ml.reload.used?).to be true
    end

    it "#expired? returns true for a past link" do
      ml = ApiAuthenticationGem::MagicLink.create!(
        identifier: email, token: "t3", expires_at: Time.now - 1
      )
      expect(ml.expired?).to be true
    end

    it ".active scope excludes used links" do
      ml = ApiAuthenticationGem::MagicLink.create!(
        identifier: email, token: "t4", expires_at: Time.now + 900
      )
      ml.consume!
      expect(ApiAuthenticationGem::MagicLink.active).not_to include(ml)
    end

    it ".active scope excludes expired links" do
      ml = ApiAuthenticationGem::MagicLink.create!(
        identifier: email, token: "t5", expires_at: Time.now - 1
      )
      expect(ApiAuthenticationGem::MagicLink.active).not_to include(ml)
    end
  end
end
