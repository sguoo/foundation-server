require 'sinatra'
require 'sinatra/activerecord'
require 'bcrypt'
require 'json'
require 'mail'
require 'securerandom'

enable :sessions

set :bind, '0.0.0.0'
set :port, 25565

set :database, {adapter: "sqlite3", database: "db/development.sqlite3"}

Mail.defaults do
  delivery_method :smtp, {
    address: "smtp.gmail.com",
    port: 587,
    user_name: 'sgoo.dsm.hs.kr',
    password: 'chu1020@',
    authentication: 'plain',
    enable_starttls_auto: true
  }
end

class User < ActiveRecord::Base
  self.primary_key = 'id'

  include BCrypt

  validates :email, presence: true, uniqueness: true

  def password
    @password ||= Password.new(password_hash)
  end

  def password=(new_password)
    @password = Password.create(new_password)
    self.password_hash = @password
  end

  attr_accessor :token
end

set :allow_origin, "*"
set :allow_methods, "GET,HEAD,POST,OPTIONS,PUT,PATCH,DELETE"
set :allow_headers, "content-type,if-modified-since"

helpers do
  def current_user
    @current_user ||= User.find(session[:user_id]) if session[:user_id]
  end

  def admin_user?
    current_user && current_user.name == 'admin'
  end

  def logged_in?
    !current_user.nil?
  end
end

#/users/new 경로는 누구나 접근할 수 있도록 예외 처리

before '/users*' do
  pass if request.path_info == '/users/new' || request.path_info == '/users/token_verification' || request.path_info == '/users/success'
  if admin_user?
    pass  # admin 사용자는 /users에 접근 가능
  else
    redirect '/'  # admin이 아닌 사용자는 /로 리다이렉트
  end
end

def read_json_file(file_path)
  file = File.read(file_path)
  JSON.parse(file)
end

get '/question' do
  content_type :json, charset: 'utf-8'
  data = read_json_file('views/question.json')
  data.to_json
end

get '/api/:data' do
  content_type :json, charset: 'utf-8'
  data = read_json_file("views/#{params[:data]}")
  data.to_json
end

get '/' do
  erb :index
end

get '/users' do
  @users = User.all
  erb :users
end

get '/users/new' do
  @error = false
  erb :new_user
end

post '/users/new' do
  if User.exists?(email: params[:email])
    @error = true
    @error_message = "이미 사용 중인 이메일입니다."
    erb :new_user
  else
    @user = User.new(id: params[:id], name: params[:name], email: params[:email], password: params[:password])
    @user.token = SecureRandom.hex(10)
    if @user.save
      session[:user_id] = @user.id
      begin
        Mail.deliver do
          to @user.email
          from 'sgoo.dsm.hs.kr'
          subject 'Account verification'
          body "Your verification token is #{@user.token}"
        end
        redirect "/users/token_verification?email=#{@user.email}"
      rescue => e
        @user.destroy
        @error = "Email delivery failed: #{e.message}"
        erb :new_user
      end
    else
      @error = "User save failed"
      erb :new_user
    end
  end
end


get '/users/token_verification' do
    @user_email = params[:email]
    @error = params[:error]
    erb :token_verification
end

post '/users/token_verification' do
    @user = User.find_by(email: params[:email])

    if @user && @user.token == params[:token]
      @user.update(verified: true)
      redirect '/users/success'
    else
      redirect "/users/token_verification?email=#{params[:email]}&error=Invalid token"
    end
end

# 성공시
get '/users/success' do
    "Account successfully created and verified."
end

get '/login' do
  @error = false
  erb :login
end

post '/login' do
  user = User.find_by(email: params[:email])
  if user && user.password == params[:password]
    session[:user_id] = user.id
    redirect '/'
  else
    @error = true
    erb :login
  end
end

get '/logout' do
  session.clear
  redirect '/'
end

get '/users/:id' do
  @user = User.find(params[:id])
  erb :show_user
end

put '/users/:id' do
  @user = User.find(params[:id])
  if @user.update(name: params[:name], email: params[:email])
    redirect "/users/#{@user.id}"
  else
    "사용자 업데이트 중 오류가 발생했습니다."
  end
end

delete '/users/:id' do
  @user = User.find(params[:id])
  if @user.destroy
    redirect '/users'
  else
    "사용자 삭제 중 오류가 발생했습니다."
  end
end

get '/users/json/:name' do
    content_type :json
    name = params[:name]
    users = User.where(name: name)
    users.to_json
end

get '/users/name/:name' do
  @user = User.find_by(name: params[:name])
  if @user
    "사용자 ID: #{@user.id}, 이름: #{@user.name}, 이메일: #{@user.email}"
  else
    "#{params[:name]} 이름을 가진 사용자가 없습니다."
  end
end
