class CreateUsers < ActiveRecord::Migration[6.0]
  def change
    create_table :users, id: false do |t|
      t.primary_key :id
      t.string :name
      t.string :email
      t.string :password_hash

      t.timestamps
    end
  end
end
