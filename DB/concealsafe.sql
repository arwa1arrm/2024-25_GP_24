-- phpMyAdmin SQL Dump
-- version 5.1.2
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3306
-- Generation Time: Oct 24, 2024 at 06:14 AM
-- Server version: 5.7.24
-- PHP Version: 8.0.1

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `concealsafe`
--

-- --------------------------------------------------------

--
-- Table structure for table `message`
--

CREATE TABLE `message` (
  `MessageID` int(11) NOT NULL,
  `EncryptedSharedKey` varchar(255) NOT NULL,
  `Content` text NOT NULL,
  `SenderID` int(11) DEFAULT NULL,
  `RecipientID` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `user_id` int(11) NOT NULL,
  `user_name` varchar(25) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `certificate` longtext NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`user_id`, `user_name`, `email`, `password`, `certificate`) VALUES
(75, 'yara', 'yara@gmail.com', '$2b$12$drXeLzBWezofdUQ0NTddMeMY6MFl2s3KpYFd4YrqO06BoJ5faXyLK', '-----BEGIN CERTIFICATE-----\nMIICqjCCAZKgAwIBAgIUStn7aoXa3bU1jSHuL8jT6ZHW0ZcwDQYJKoZIhvcNAQEL\nBQAwDzENMAsGA1UEAwwEeWFyYTAeFw0yNDEwMjQwNjExNTBaFw0yNTEwMjQwNjEx\nNTBaMA8xDTALBgNVBAMMBHlhcmEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQDAmiwg4OE/h8Fril6wc5bsmOWQKJk0mlcDieDtuTU9QQsHZJFPW7LjOqXw\nz47eJiQXEwvT7r9MmwVj9BIM2eSCYvWC+/SpQBDTnbXf6vCIhzMvYqu2ySww+wK7\nBo2icTgPBSFixJJ/tZ7dRWr33Q6lO5w3W5745LYLqMHIltA1ASz+rHDNzCRSuvTv\nGF5/C/JfjW1OQTi5euENqRtxZdB2YVi0+HSRHlH5tw6oLjzAqWLcrNuyb/UAVvsN\niT7yCWxKGkJCN7EZP+KN7nBTagIZTpcpLvzRuKXfkrx+z7hU+S6+G3T3W2Fk451y\nGHZbiKTOPmBnscsdNil3GMdFvR9tAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADoe\nDAbleBmORjMbvtSTqhoKQoAsBa8dybmS7w/c1r6IE2+sjKWb+kZ9ivUg8+k6/8Aj\n8yafEPyKOyKwc2uAPrqTyVuj2hw7ZbnxKHDgv2nVxp2LfPC8GDzBHufIu5sd3LHQ\niblqL82Ed5Raf25mAE4aQqCAksJga7SCZFdd6u9bTg4j6sNmdJ0bIDFhSLe9QfZX\na/FUoNDa1huGYFw2T6Dgxh3XN4qRG50GXXJsiU3MRsv0B7wSaLwlNfraumCN9zuy\nIN8G9yoooUZxuXOJy3rYOs5Ghk+SLFzhl7z4EHXKLygvUnDftqwiqLucL/1/YwVM\nbdhF2UVo0ZGevaTydYM=\n-----END CERTIFICATE-----\n');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `message`
--
ALTER TABLE `message`
  ADD PRIMARY KEY (`MessageID`),
  ADD KEY `SenderID` (`SenderID`),
  ADD KEY `RecipientID` (`RecipientID`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`user_id`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `user_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=76;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `message`
--
ALTER TABLE `message`
  ADD CONSTRAINT `message_ibfk_1` FOREIGN KEY (`SenderID`) REFERENCES `users` (`user_id`),
  ADD CONSTRAINT `message_ibfk_2` FOREIGN KEY (`RecipientID`) REFERENCES `users` (`user_id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
