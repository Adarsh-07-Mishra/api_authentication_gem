require "jwt"
module ApiAuthenticationGem
  class Auth
    def self.signup(email:, password:)
      user_class = ApiAuthenticationGem.configuration.user_class.constantize
      user = user_class.create!(email: email, password: password)
      token = generate_token(user.id)
      { token: token, user: user }
    end
    
    def self.login(email:, password:)
      user_class = ApiAuthenticationGem.configuration.user_class.constantize
      user = user_class.find_by(email: email)
      return nil unless user&.authenticate(password)
    
      token = generate_token(user.id)
      { token: token, user: user }
    end
    

    # Decode the JWT token and retrieve the payload
    def self.decode(token)
      decoded = JWT.decode(token, ApiAuthenticationGem.configuration.secret_key, true, algorithm: 'HS256')
      decoded.first # The payload is in the first element
    rescue JWT::DecodeError => e
      nil # If the token is invalid, return nil
    end

    private

    def self.generate_token(user_id)
      payload = { user_id: user_id }
      JWT.encode(payload, ApiAuthenticationGem.configuration.secret_key)
    end
  end
end
