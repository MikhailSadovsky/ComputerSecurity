DROP TABLE USER_RESOURCE_PERMISSIONS;
DROP TABLE USER;
DROP TABLE RESOURCE;
DROP TABLE PERMISSION;


CREATE TABLE IF NOT EXISTS USER (
         ID INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
         LOGIN VARCHAR(250) NOT NULL UNIQUE,
         EMAIL VARCHAR(250) NOT NULL UNIQUE,
         PASSWORD VARCHAR(250) NOT NULL,
         ROLE INT 
);

CREATE TABLE IF NOT EXISTS RESOURCE (
         ID INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
         NAME VARCHAR(1000) NOT NULL,
         INFO VARCHAR(1000) NOT NULL
);

CREATE TABLE IF NOT EXISTS PERMISSION (
         BIT INT(11) NOT NULL PRIMARY KEY,
         NAME VARCHAR(50) NOT NULL
);

CREATE TABLE IF NOT EXISTS USER_RESOURCE_PERMISSIONS (
		 ID INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
         USER_ID INT NOT NULL,
         RESOURCE_ID INT NOT NULL,
         PERMISSION INT,
         FOREIGN KEY (USER_ID) REFERENCES USER(ID) ON DELETE CASCADE,
		 FOREIGN KEY (RESOURCE_ID) REFERENCES RESOURCE(ID) ON DELETE CASCADE
);
       
/* password for nosti_admin is nosti, for sample_user is sample_user */
INSERT INTO USER (LOGIN, EMAIL, PASSWORD, ROLE) VALUES ('nosti_admin', 'nosti@mail.ru', '$2a$10$Q3qzVQNgUBWO1VTgT0YW7u/RWoWCznnLOv9.eEE9YraqTW9O8QOHy', 1);
INSERT INTO USER (LOGIN, EMAIL, PASSWORD, ROLE) VALUES ('sample_user', 'sample_user@mail.ru', '$2a$10$McGXjrn...KK0wHwEKM4cOiKmeVVclWC7meAySB6pcXtEL3lDh0TG', 0);
INSERT INTO PERMISSION (BIT, NAME) VALUES
         (2, 'Edit'),
         (4, 'Delete'),
         (8, 'View');
INSERT INTO RESOURCE (NAME, INFO) VALUES ('First resource', 'First resource info');
INSERT INTO USER_RESOURCE_PERMISSIONS (USER_ID, RESOURCE_ID, PERMISSION) VALUES (2, 1, 6);
 