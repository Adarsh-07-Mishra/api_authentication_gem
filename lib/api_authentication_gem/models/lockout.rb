module ApiAuthenticationGem
  class Lockout < ::ActiveRecord::Base
    self.table_name = "api_auth_lockouts"

    validates :identifier, presence: true, uniqueness: true

    def locked?
      locked_until.present? && locked_until > Time.now
    end

    def minutes_remaining
      return 0 unless locked?

      ((locked_until - Time.now) / 60).ceil
    end

    def reset!
      update!(failed_attempts: 0, locked_until: nil)
    end
  end
end
