module ApiAuthenticationGem
  module Concerns
    module Authenticatable
      def self.included(base)
        base.helper_method :current_user if base.respond_to?(:helper_method)
      end

      # Decodes the Authorization header, sets @current_user.
      # Renders 401 and returns false on any failure — the action never runs.
      def authenticate_user!
        token = extract_bearer_token
        unless token
          render json: { error: "Authorization token missing" }, status: :unauthorized
          return false
        end

        decoded = ApiAuthenticationGem::Auth.decode(token)
        unless decoded
          render json: { error: "Invalid or expired token" }, status: :unauthorized
          return false
        end

        user_id    = decoded["sub"] || decoded["user_id"]
        user_class = ApiAuthenticationGem.configuration.user_class.constantize
        @current_user = user_class.find_by(id: user_id)

        unless @current_user
          render json: { error: "User not found" }, status: :unauthorized
          return false
        end

        true
      end

      # Role-based access control guard.
      # Call after authenticate_user! has already set @current_user.
      #
      # Usage:
      #   before_action -> { authorize_role!(:admin) }
      #   before_action -> { authorize_role!(:admin, :moderator) }
      #
      # Returns true when allowed; renders 403 and returns false otherwise.
      def authorize_role!(*allowed_roles)
        unless current_user
          render json: { error: "Not authenticated" }, status: :unauthorized
          return false
        end

        config     = ApiAuthenticationGem.configuration
        user_role  = current_user.public_send(config.role_attribute).to_s
        allowed    = allowed_roles.map(&:to_s)

        unless allowed.include?(user_role)
          render json: {
            error:    "Forbidden: insufficient permissions",
            required: allowed,
            current:  user_role
          }, status: :forbidden
          return false
        end

        true
      end

      def current_user
        @current_user
      end

      private

      def extract_bearer_token
        header = request.headers["Authorization"]
        return nil unless header.present?

        header.start_with?("Bearer ") ? header.split(" ", 2).last.strip : header.strip
      end
    end
  end
end
