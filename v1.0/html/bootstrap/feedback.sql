su - postgres

psql -d enhancedip_feedback; 

CREATE DATABASE enhancedip_feedback;

CREATE table feedback(name VARCHAR(20), email VARCHAR(50), comments VARCHAR(400), date DATE, ipaddress VARCHAR(20));

INSERT INTO feedback 'Sam', 'sam@enhancedip.org', 'comments by sam', '2012-04-11', '1.2.3.4';
