create database argus;
use argus;

create table authorized_users(
authUserID int primary key identity,
username varchar(20) not null,
password varchar(255) not null,
created_by varchar(30) not null,
comments varchar(512) not null
);

INSERT INTO authorized_users VALUES ('marshal', '$2a$12$hiYZeavSnrgWGa8AgIOlrOAKdh2pg4r9PblGXWi91al1cJMmaopXO', 'Administrator', 'Test account');

SELECT * FROM authorized_users;

drop table authorized_users;
truncate table authorized_users;