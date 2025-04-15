require "jwt"
require "bcrypt"

module ApiAuthenticationGem
  class Auth
    SECRET_KEY = "your$ecretK3y"

    def self.signup(email:, password:, user_class:)
      return { error: "Email is required" } unless email
      return { error: "Password must be at least 5 characters long" } if password.nil? || password.length < 5

      return { error: "Email already exists" } if user_class.find_by(email: email)

      password_digest = BCrypt::Password.create(password)
      user = user_class.create(email: email, password_digest: password_digest)

      { message: "User created", user: user }
    end

    def self.login(email:, password:, user_class:)
      user = user_class.find_by(email: email)

      return { error: "Invalid email or password" } unless user
      return { error: "Invalid email or password" } unless BCrypt::Password.new(user.password_digest) == password

      token = JWT.encode({ user_id: user.id, exp: Time.now.to_i + 3600 }, SECRET_KEY, 'HS256')
      { token: token }
    end

    def self.decode_token(token)
      JWT.decode(token, SECRET_KEY, true, { algorithm: 'HS256' })[0]
    rescue
      nil
    end
  end
end
