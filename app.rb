require 'sinatra'
require 'sinatra/activerecord'
require 'bcrypt'

enable :sessions

set :bind, '0.0.0.0'

set :database, {adapter: "sqlite3", database: "db/development.sqlite3"}

class User < ActiveRecord::Base
  self.primary_key = 'id'  # 기본 키를 명시적으로 설정

  include BCrypt

  def password
    @password ||= Password.new(password_hash)
  end

  def password=(new_password)
    @password = Password.create(new_password)
    self.password_hash = @password
  end
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
  pass if request.path_info == '/users/new'
  if admin_user?
    pass  # admin 사용자는 /users에 접근 가능
   else
    redirect '/'  # admin이 아닌 사용자는 /로 리다이렉트
  end
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
  if User.exists?(name: params[:name])
    @error = true
    erb :new_user
  else
    @user = User.new(id: params[:id], name: params[:name], email: params[:email], password: params[:password])
    if @user.save
      session[:user_id] = @user_id
      "사용자가 생성되었습니다. ID: #{@user.id}, Name: #{@user.name}, Email: #{@user.email}"
    else
      "사용자 저장 중 오류가 발생했습니다: #{@user.errors.full_messages.join(', ')}"
    end
  end
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

get '/users/name/:name' do
  @user = User.find_by(name: params[:name])
  if @user
    "사용자 ID: #{@user.id}, 이름: #{@user.name}, 이메일: #{@user.email}"
  else
    "#{params[:name]} 이름을 가진 사용자가 없습니다."
  end
end
