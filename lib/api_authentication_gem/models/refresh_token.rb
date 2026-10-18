module ApiAuthenticationGem
  class RefreshToken < ::ActiveRecord::Base
    self.table_name = "api_auth_refresh_tokens"

    validates :user_id, :token, :expires_at, presence: true
    validates :token, uniqueness: true

    scope :active, -> { where(revoked_at: nil).where("expires_at > ?", Time.now) }

    def active?
      revoked_at.nil? && expires_at > Time.now
    end

    def revoke!
      update!(revoked_at: Time.now)
    end
  end
end
