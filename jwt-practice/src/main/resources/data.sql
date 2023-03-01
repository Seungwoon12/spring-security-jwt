insert into member (member_id, member_name, password, nickname, activated) values (1, 'admin', '$2a$12$J3gycqXMj8Pqk9lHq5eSoufmJQNhDLlm1lzp80/aBsN2.jJqVtcZC', 'admin', 1);


insert into authority (authority_name) values ('ROLE_USER');
insert into authority (authority_name) values ('ROLE_ADMIN');

insert into user_authority (member_id, authority_name) values (1, 'ROLE_USER');
insert into user_authority (member_id, authority_name) values (1, 'ROLE_ADMIN');
