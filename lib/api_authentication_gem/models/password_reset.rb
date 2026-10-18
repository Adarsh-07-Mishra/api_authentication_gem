module ApiAuthenticationGem
  class PasswordReset < ::ActiveRecord::Base
    self.table_name = "api_auth_password_resets"

    validates :identifier, :token, :expires_at, presence: true
    validates :token, uniqueness: true

    # Only tokens that haven't been used and haven't expired
    scope :active, -> { where(used_at: nil).where("expires_at > ?", Time.now) }

    def expired?
      expires_at <= Time.now
    end

    def used?
      !used_at.nil?
    end

    def consume!
      update!(used_at: Time.now)
    end
  end
end
