module ApiAuthenticationGem
  class AuthSession < ::ActiveRecord::Base
    self.table_name = "api_auth_sessions"

    validates :user_id, :jti, :expires_at, presence: true
    validates :jti, uniqueness: true

    scope :active, -> { where(revoked_at: nil).where("expires_at > ?", Time.now) }

    def active?
      revoked_at.nil? && expires_at > Time.now
    end

    def revoke!
      update!(revoked_at: Time.now)
    end
  end
end
