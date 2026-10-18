require "rails_helper"

RSpec.describe "Account Lockout — ApiAuthenticationGem::Auth login lockout" do
  before do
    ApiAuthenticationGem.reset_configuration!
    ApiAuthenticationGem.configure do |config|
      config.secret_key          = "test-secret-for-lockout"
      config.user_class          = "User"
      config.lockout_enabled     = true
      config.max_login_attempts  = 3
      config.lockout_duration    = 900  # 15 minutes in seconds
    end
  end

  let(:email)    { "lockout@example.com" }
  let(:password) { "securepass" }

  before { ApiAuthenticationGem::Auth.signup(email: email, password: password) }

  def fail_login(n = 1)
    n.times { ApiAuthenticationGem::Auth.login(email: email, password: "wrongpassword") }
  end

  # ---------------------------------------------------------------------------
  # Failed attempt tracking
  # ---------------------------------------------------------------------------
  describe "failed attempt tracking" do
    it "does not lock account before max_login_attempts is reached" do
      fail_login(2)  # one shy of the limit

      result = ApiAuthenticationGem::Auth.login(email: email, password: password)
      expect(result[:token]).to be_a(String)
      expect(result[:error]).to be_nil
    end

    it "increments failed_attempts in the DB on each bad login" do
      fail_login(2)
      record = ApiAuthenticationGem::Lockout.find_by(identifier: email)
      expect(record.failed_attempts).to eq(2)
    end

    it "locks the account after max_login_attempts consecutive failures" do
      fail_login(3)  # hits the limit

      result = ApiAuthenticationGem::Auth.login(email: email, password: password)
      expect(result[:error]).to include("Account locked")
    end

    it "returns the number of minutes remaining when locked" do
      fail_login(3)

      result = ApiAuthenticationGem::Auth.login(email: email, password: password)
      expect(result[:error]).to match(/Try again in \d+ minute/)
    end

    it "resets failed_attempts counter after a lock is applied" do
      fail_login(3)
      record = ApiAuthenticationGem::Lockout.find_by(identifier: email)
      # counter resets to 0 once the lock is placed
      expect(record.failed_attempts).to eq(0)
      expect(record.locked_until).to be > Time.now
    end
  end

  # ---------------------------------------------------------------------------
  # Successful login clears lockout state
  # ---------------------------------------------------------------------------
  describe "successful login" do
    it "clears failed_attempts after a correct login" do
      fail_login(2)

      ApiAuthenticationGem::Auth.login(email: email, password: password)

      record = ApiAuthenticationGem::Lockout.find_by(identifier: email)
      expect(record.failed_attempts).to eq(0)
      expect(record.locked_until).to be_nil
    end

    it "clears the lockout after the lockout_duration has passed" do
      fail_login(3)

      # Simulate time passing by backdating locked_until
      ApiAuthenticationGem::Lockout
        .find_by(identifier: email)
        .update!(locked_until: Time.now - 1)

      result = ApiAuthenticationGem::Auth.login(email: email, password: password)
      expect(result[:token]).to be_a(String)
      expect(result[:error]).to be_nil
    end
  end

  # ---------------------------------------------------------------------------
  # Lockout is per-identifier
  # ---------------------------------------------------------------------------
  describe "lockout isolation" do
    it "locking one email does not affect another" do
      other_email = "other@example.com"
      ApiAuthenticationGem::Auth.signup(email: other_email, password: password)

      fail_login(3)  # lock the main email

      # Other account should still work
      result = ApiAuthenticationGem::Auth.login(email: other_email, password: password)
      expect(result[:token]).to be_a(String)
      expect(result[:error]).to be_nil
    end
  end

  # ---------------------------------------------------------------------------
  # Lockout disabled
  # ---------------------------------------------------------------------------
  describe "when lockout_enabled is false" do
    before { ApiAuthenticationGem.configuration.lockout_enabled = false }

    it "does not track failed attempts" do
      fail_login(10)
      expect(ApiAuthenticationGem::Lockout.count).to eq(0)
    end

    it "never locks the account regardless of failed attempts" do
      fail_login(10)
      result = ApiAuthenticationGem::Auth.login(email: email, password: password)
      expect(result[:token]).to be_a(String)
    end
  end

  # ---------------------------------------------------------------------------
  # Lockout model
  # ---------------------------------------------------------------------------
  describe "ApiAuthenticationGem::Lockout model" do
    it "#locked? returns false when locked_until is nil" do
      lo = ApiAuthenticationGem::Lockout.create!(
        identifier: email, failed_attempts: 0
      )
      expect(lo.locked?).to be false
    end

    it "#locked? returns false when locked_until is in the past" do
      lo = ApiAuthenticationGem::Lockout.create!(
        identifier: email, failed_attempts: 0, locked_until: Time.now - 1
      )
      expect(lo.locked?).to be false
    end

    it "#locked? returns true when locked_until is in the future" do
      lo = ApiAuthenticationGem::Lockout.create!(
        identifier: email, failed_attempts: 0, locked_until: Time.now + 900
      )
      expect(lo.locked?).to be true
    end

    it "#minutes_remaining returns a positive integer when locked" do
      lo = ApiAuthenticationGem::Lockout.create!(
        identifier: email, failed_attempts: 0, locked_until: Time.now + 900
      )
      expect(lo.minutes_remaining).to be > 0
    end

    it "#minutes_remaining returns 0 when not locked" do
      lo = ApiAuthenticationGem::Lockout.create!(
        identifier: email, failed_attempts: 0
      )
      expect(lo.minutes_remaining).to eq(0)
    end

    it "#reset! clears failed_attempts and locked_until" do
      lo = ApiAuthenticationGem::Lockout.create!(
        identifier:      email,
        failed_attempts: 3,
        locked_until:    Time.now + 900
      )
      lo.reset!
      lo.reload
      expect(lo.failed_attempts).to eq(0)
      expect(lo.locked_until).to be_nil
    end
  end
end
