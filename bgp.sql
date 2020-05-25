CREATE DATABASE IF NOT EXISTS `bgp` DEFAULT CHARACTER SET utf16 COLLATE utf16_general_ci;
USE `bgp`;


DROP TABLE IF EXISTS `addv4`;
CREATE TABLE `addv4` (
  `asn` varchar(10) CHARACTER SET utf16 NOT NULL,
  `prefix` varchar(50) CHARACTER SET utf16 NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf16;

DROP TABLE IF EXISTS `addv6`;
CREATE TABLE `addv6` (
  `asn` varchar(10) CHARACTER SET utf16 NOT NULL,
  `prefix` varchar(50) CHARACTER SET utf16 NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf16;


DROP TABLE IF EXISTS `asns`;
CREATE TABLE `asns` (
  `asn` varchar(10) CHARACTER SET utf16 NOT NULL,
  `peerv4` varchar(15) CHARACTER SET utf16,
  `peerv6` varchar(39) CHARACTER SET utf16,
  `asset` varchar(50) CHARACTER SET utf16,
  `maxv4` varchar(12),
  `maxv6` varchar(12),
  `md5` varchar(255) CHARACTER SET utf16,
  `legalname` varchar(255) CHARACTER SET utf16 NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf16;


DROP TABLE IF EXISTS `deletev4`;
CREATE TABLE `deletev4` (
  `asn` varchar(10) CHARACTER SET utf16 NOT NULL,
  `prefix` varchar(50) CHARACTER SET utf16 NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf16;

DROP TABLE IF EXISTS `deletev6`;
CREATE TABLE `deletev6` (
  `asn` varchar(10) CHARACTER SET utf16 NOT NULL,
  `prefix` varchar(50) CHARACTER SET utf16 NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf16;




