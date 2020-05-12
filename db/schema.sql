--- load with 
--- sqlite3 database.db < schema.sql

CREATE TABLE IF NOT EXISTS user(
	username VARCHAR(60) PRIMARY KEY,
	passwordHash CHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS userKeys(
	username VARCHAR(60) PRIMARY KEY,
	publicKey CHAR(194) NOT NULL,
	privateKeyEncrypted VARCHAR(256) NOT NULL,
	encryption_iv VARCHAR(256) NOT NULL,
	FOREIGN KEY (username) REFERENCES user(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS friends(
	friend1 VARCHAR(60),
	friend2 VARCHAR(60),
	PRIMARY KEY (friend1, friend2),
	FOREIGN KEY (friend1) REFERENCES user(username) ON DELETE CASCADE,
	FOREIGN KEY (friend2) REFERENCES user(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS message(
	sender VARCHAR(60),
	recipient VARCHAR(60),
	messageEncrypted VARCHAR(256) NOT NULL,
	encryption_iv VARCHAR(256) NOT NULL,
	timestamp CHAR(24) NOT NULL,
	PRIMARY KEY (sender, recipient, timestamp),
	FOREIGN KEY (sender) REFERENCES user(username) ON DELETE CASCADE,
	FOREIGN KEY (recipient) REFERENCES user(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS friendRequest(
	requester VARCHAR(60),
	requestee VARCHAR(60),
	PRIMARY KEY (requester, requestee),
	FOREIGN KEY (requester) REFERENCES user(username) ON DELETE CASCADE,
	FOREIGN KEY (requestee) REFERENCES user(username) ON DELETE CASCADE
);


/* Enforce messages only between friends */
CREATE TRIGGER do_i_know_you
   BEFORE INSERT ON message

BEGIN
	SELECT
      CASE
          WHEN NOT EXISTS(SELECT * 
              FROM friends
              WHERE NEW.sender IN (friend1, friend2)
              AND NEW.recipient IN (friend1, friend2)
          ) THEN 
          RAISE (ABORT, "You can't send messages to this person, you aren't friends.")
      END;
END;

/* 
This trigger prevents this: db < friendRequest~(a,b) and then db < friendRequest~(b,a).
If there exists some friendRequest~(a,b), then they should just become friends and remove (a,b),
instead of having 2 requests (a,b) and (b,a).

Also prevents friend requests to users who already friends.
 */


CREATE TRIGGER check_duplicates_trigger
   BEFORE INSERT ON friendRequest

BEGIN
	SELECT
      CASE
          WHEN EXISTS(SELECT * 
              FROM friendRequest fr 
              WHERE NEW.requester = fr.requestee
              AND fr.requester = NEW.requestee
          ) THEN 
          RAISE (ABORT, "Friend request has already been mirrored.")

          WHEN EXISTS(SELECT *
          	FROM friends
          	WHERE NEW.requester IN (friend1, friend2)
          	AND NEW.requestee IN (friend1, friend2)
          ) THEN 
          RAISE (ABORT, 'Already friends.')
      END;
END;

/* consider adding a trigger that automatically adds to friends and 
deletes from friendRequest when mirrored requests */
