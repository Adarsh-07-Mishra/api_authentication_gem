require "rails_helper"

RSpec.describe "Password Reset — ApiAuthenticationGem::Auth password reset flow" do
  before do
    ApiAuthenticationGem.reset_configuration!
    ApiAuthenticationGem.configure do |config|
      config.secret_key            = "test-secret-for-password-reset"
      config.user_class            = "User"
      config.password_reset_expiry = 15 * 60 # 15 minutes
      config.min_password_length   = 6
    end
    ApiAuthenticationGem::Auth.signup(email: email, password: password)
  end

  let(:email)    { "reset@example.com" }
  let(:password) { "oldpassword" }

  # ---------------------------------------------------------------------------
  # request_password_reset
  # ---------------------------------------------------------------------------
  describe ".request_password_reset" do
    context "with a registered email" do
      it "returns the standard message and a reset_token" do
        result = ApiAuthenticationGem::Auth.request_password_reset(email: email)

        expect(result[:error]).to be_nil
        expect(result[:message]).to eq("If that email is registered, a reset token has been sent.")
        expect(result[:reset_token]).to be_a(String)
        expect(result[:reset_token].length).to be >= 20
      end

      it "stores a PasswordReset record in the DB" do
        result = ApiAuthenticationGem::Auth.request_password_reset(email: email)
        record = ApiAuthenticationGem::PasswordReset.find_by(token: result[:reset_token])

        expect(record).not_to be_nil
        expect(record.identifier).to eq(email)
        expect(record.used_at).to be_nil
        expect(record.expires_at).to be > Time.now
      end

      it "invalidates the previous reset token when a new one is requested" do
        r1 = ApiAuthenticationGem::Auth.request_password_reset(email: email)
        r2 = ApiAuthenticationGem::Auth.request_password_reset(email: email)

        old_record = ApiAuthenticationGem::PasswordReset.find_by(token: r1[:reset_token])
        expect(old_record.used_at).not_to be_nil   # consumed when new one was issued

        new_record = ApiAuthenticationGem::PasswordReset.find_by(token: r2[:reset_token])
        expect(new_record.used_at).to be_nil       # fresh one is still active
      end

      it "each request generates a unique token" do
        r1 = ApiAuthenticationGem::Auth.request_password_reset(email: email)
        # invalidate first so second can be created fresh
        ApiAuthenticationGem::PasswordReset.find_by(token: r1[:reset_token]).consume!
        r2 = ApiAuthenticationGem::Auth.request_password_reset(email: email)
        expect(r1[:reset_token]).not_to eq(r2[:reset_token])
      end
    end

    context "with an unregistered email" do
      it "returns the same message (no enumeration) and no reset_token" do
        result = ApiAuthenticationGem::Auth.request_password_reset(
          email: "nobody@example.com"
        )

        expect(result[:message]).to eq("If that email is registered, a reset token has been sent.")
        expect(result[:reset_token]).to be_nil
        expect(result[:error]).to be_nil
      end
    end

    context "with a blank email" do
      it "returns an error" do
        result = ApiAuthenticationGem::Auth.request_password_reset(email: "")
        expect(result[:error]).to eq("Email is required")
      end
    end
  end

  # ---------------------------------------------------------------------------
  # reset_password
  # ---------------------------------------------------------------------------
  describe ".reset_password" do
    let(:new_password) { "newpassword" }

    def get_reset_token
      ApiAuthenticationGem::Auth
        .request_password_reset(email: email)[:reset_token]
    end

    context "with a valid token" do
      it "resets the password and returns a success message" do
        token  = get_reset_token
        result = ApiAuthenticationGem::Auth.reset_password(
          reset_token:  token,
          new_password: new_password
        )

        expect(result[:error]).to be_nil
        expect(result[:message]).to eq("Password has been reset successfully")
      end

      it "marks the reset token as used" do
        token = get_reset_token
        ApiAuthenticationGem::Auth.reset_password(
          reset_token: token, new_password: new_password
        )
        record = ApiAuthenticationGem::PasswordReset.find_by(token: token)
        expect(record.used?).to be true
        expect(record.used_at).not_to be_nil
      end

      it "allows login with the new password after reset" do
        token = get_reset_token
        ApiAuthenticationGem::Auth.reset_password(
          reset_token: token, new_password: new_password
        )

        result = ApiAuthenticationGem::Auth.login(email: email, password: new_password)
        expect(result[:token]).to be_a(String)
        expect(result[:error]).to be_nil
      end

      it "old password no longer works after reset" do
        token = get_reset_token
        ApiAuthenticationGem::Auth.reset_password(
          reset_token: token, new_password: new_password
        )

        result = ApiAuthenticationGem::Auth.login(email: email, password: password)
        expect(result[:error]).to eq("Invalid email or password")
      end
    end

    context "with an already-used token" do
      it "returns an error" do
        token = get_reset_token
        ApiAuthenticationGem::Auth.reset_password(reset_token: token, new_password: new_password)

        # Try to reuse
        result = ApiAuthenticationGem::Auth.reset_password(
          reset_token: token, new_password: "anotherpass"
        )
        expect(result[:error]).to eq("Invalid or expired reset token")
      end
    end

    context "with an expired token" do
      it "returns an error" do
        token = get_reset_token

        # Force-expire the record
        ApiAuthenticationGem::PasswordReset
          .find_by(token: token)
          .update!(expires_at: Time.now - 1)

        result = ApiAuthenticationGem::Auth.reset_password(
          reset_token: token, new_password: new_password
        )
        expect(result[:error]).to eq("Invalid or expired reset token")
      end
    end

    context "with a too-short new password" do
      it "returns an error before touching the DB" do
        token  = get_reset_token
        result = ApiAuthenticationGem::Auth.reset_password(
          reset_token: token, new_password: "abc"
        )
        expect(result[:error]).to include("at least")

        # Token should still be active (not consumed)
        record = ApiAuthenticationGem::PasswordReset.find_by(token: token)
        expect(record.used?).to be false
      end
    end

    context "with a blank reset token" do
      it "returns an error" do
        result = ApiAuthenticationGem::Auth.reset_password(
          reset_token: "", new_password: new_password
        )
        expect(result[:error]).to eq("Reset token is required")
      end
    end

    context "with a nil reset token" do
      it "returns an error" do
        result = ApiAuthenticationGem::Auth.reset_password(
          reset_token: nil, new_password: new_password
        )
        expect(result[:error]).to eq("Reset token is required")
      end
    end

    context "with a completely fake token" do
      it "returns an error" do
        result = ApiAuthenticationGem::Auth.reset_password(
          reset_token: "made-up-token", new_password: new_password
        )
        expect(result[:error]).to eq("Invalid or expired reset token")
      end
    end
  end

  # ---------------------------------------------------------------------------
  # PasswordReset model
  # ---------------------------------------------------------------------------
  describe "ApiAuthenticationGem::PasswordReset model" do
    it "#used? returns false for a fresh token" do
      pr = ApiAuthenticationGem::PasswordReset.create!(
        identifier: email, token: "tok1", expires_at: Time.now + 3600
      )
      expect(pr.used?).to be false
    end

    it "#used? returns true after consume!" do
      pr = ApiAuthenticationGem::PasswordReset.create!(
        identifier: email, token: "tok2", expires_at: Time.now + 3600
      )
      pr.consume!
      expect(pr.reload.used?).to be true
    end

    it "#expired? returns false for a future token" do
      pr = ApiAuthenticationGem::PasswordReset.create!(
        identifier: email, token: "tok3", expires_at: Time.now + 3600
      )
      expect(pr.expired?).to be false
    end

    it "#expired? returns true for a past token" do
      pr = ApiAuthenticationGem::PasswordReset.create!(
        identifier: email, token: "tok4", expires_at: Time.now - 1
      )
      expect(pr.expired?).to be true
    end

    it ".active scope excludes used tokens" do
      pr = ApiAuthenticationGem::PasswordReset.create!(
        identifier: email, token: "tok5", expires_at: Time.now + 3600
      )
      pr.consume!
      expect(ApiAuthenticationGem::PasswordReset.active).not_to include(pr)
    end

    it ".active scope excludes expired tokens" do
      pr = ApiAuthenticationGem::PasswordReset.create!(
        identifier: email, token: "tok6", expires_at: Time.now - 1
      )
      expect(ApiAuthenticationGem::PasswordReset.active).not_to include(pr)
    end
  end
end
