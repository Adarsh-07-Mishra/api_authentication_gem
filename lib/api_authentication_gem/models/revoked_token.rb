module ApiAuthenticationGem
  class RevokedToken < ::ActiveRecord::Base
    self.table_name = "api_auth_revoked_tokens"

    validates :jti, :expires_at, presence: true
    validates :jti, uniqueness: true

    def self.revoked?(jti)
      return false if jti.nil?

      where(jti: jti).exists?
    end

    # Prune entries whose tokens have already expired — safe to call from a cron job.
    def self.cleanup!
      where("expires_at < ?", Time.now).delete_all
    end
  end
end
