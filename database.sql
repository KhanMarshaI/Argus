create database argus;
use argus;

create table authorized_users(
authUserID int primary key identity,
username varchar(20) not null,
password varchar(255) not null
);
