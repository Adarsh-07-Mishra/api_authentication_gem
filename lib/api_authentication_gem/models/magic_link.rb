module ApiAuthenticationGem
  class MagicLink < ::ActiveRecord::Base
    self.table_name = "api_auth_magic_links"

    validates :identifier, :token, :expires_at, presence: true
    validates :token, uniqueness: true

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
