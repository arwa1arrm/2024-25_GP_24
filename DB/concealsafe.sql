-- phpMyAdmin SQL Dump
-- version 5.1.2
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3306
-- Generation Time: Nov 30, 2024 at 04:00 PM
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
  `EncryptedSharedKeyReceiver` varchar(5000) NOT NULL,
  `EncryptedSharedKeySender` varchar(5000) NOT NULL,
  `Content` text NOT NULL,
  `SenderID` int(11) DEFAULT NULL,
  `RecipientID` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `message`
--

INSERT INTO `message` (`MessageID`, `EncryptedSharedKeyReceiver`, `EncryptedSharedKeySender`, `Content`, `SenderID`, `RecipientID`) VALUES
(3, 'TQWEid8DlHBIKmckahnUUP0XNJrpMhHuk3KK5y2vX1nDlMiUqDDDUO5LnD2GeDovbimb3dv6GMQ6eB8c7nAox3evma4BdaOH+mmeMiO5dpd7GIHEYLABNJXIPwH6M8Ki+pCFZzzrnTemEb8GtTFIa7TbukHGNi1rOWKWj5b1QFJRJnVfLZXhWpJ8V2Ugx2TzDqgDueHyOK3eHBxnDP49sYUVm13HnuTy0jujkJ0UYanGQgcWJEe+kraD8+GoDdwJcEGWv6hNE3ZFiy28FvR5YCrJKOAZ0HEoSD2d4vjhdXWYlsXuHbcQbXTC23JBqUKXTZOwyovvL3dtdi/bK+KBGQ==', 'fgaCWG7DybBBYg+5uiJgCo7M9SSnAy17jspz6bpLu+iYtl+LdUtbA6ZbOkjhtfSZFIIizstpjaVf0XGea4SNPmld8DLJ+hdA10yltiZzSwhq1pEl0YFYsAuPgMQeuVgihalhMNGfGDFNxQXd3t1prh8/WI//8pPxc+dY089bLsSlDwaBvl7A2rwMyVF8mUFVOOykROK24fNITfKLVpycp0/uWg66QIEYcnAQp6aMk8ydvLo9PJKgKEpKWMy1o60aq7fULPe8vWI79eSQshchn0EaaMDKeSf6M0xCAw9KaQFG3mHePscooQHRNDHqRJUFRyeWMfICEaHKCwmO3KxuWA==', 'TI4tFUa+B6hiJ7mf3UbwQBObxYckkM9h7zyOvn+UX13WoCgeaXNtzGvrR/bE/Zq9', 131, 129);

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
(129, 'yara', 'yoyoalsubhi@gmail.com', '$2b$12$3fyYsf1OsuuJ/.vjCLthne4z7JZgoCIWw3YAj67RNC0sYrJUjKRHK', '-----BEGIN CERTIFICATE-----\nMIICqjCCAZKgAwIBAgIUC5Vrj/5a6RfXIspJxJ5jponGhScwDQYJKoZIhvcNAQEL\nBQAwDzENMAsGA1UEAwwEeWFyYTAeFw0yNDExMzAxMzQ3MjBaFw0yNTExMzAxMzQ3\nMjBaMA8xDTALBgNVBAMMBHlhcmEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQCEZ9YrEerplZ1FZ3yhgksUfb4ZImvNGTTiNKGXq4K5KPztank8HFQF03kB\nxHZNiEzcJl68OJnUn8wMXRsx5jxbPxP27rnhDgNcNlb16D3oJolAa8nTembcrxrA\nl+CMDIZnRUBEF5PayLs9Bs2f//t0zGLAJzhUtMTST4CQAv3XDRFwsk8n7uCiZPBA\nOt6F+T8wggcC2+vriL8oRCeXSj86MWOysrxdqZOltNgc+2jFbnVWVP+Lo996Q3zp\naoRnTubuVONAP/sF3L+CGRXVWgBgwpdkPiVzfDFBlm8OcXXE3anf1X81lGXwj7BO\nA9+A81vqqDENK3xoWfXav3dsQ75DAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEwi\neGBYjzkZPguWkmkJb7UfDpRpv1OfSL533BPHdrU3OAkB1nTPfSrizpAuz7ghawwy\nFX9NptWusnEnUVaFUAfPEqvli3qCVcCohcDTjfIeC1gosdNzeW54IvAMucBl6GF7\n4Yb2VynLFlks1xjeS03xL6CgekH0M0FMMFfq8FzjWXbBvhVSVguUPxNgGwnSett4\nxnQkwP/nhOgb5te30VEPaiaJZG0PWBzRmJ5xc0s8Y1vKsgM94w6sIRldQGoYpxxc\n5wRBuQcgoRZVwKwq1QCw7G/p5xMS9gopZmTsQNy28rmjZrWYEmpWkMlR7llMjb0Y\ngWRGqcmGGuIlvwyFblY=\n-----END CERTIFICATE-----\n'),
(131, 'Sarah', 'yalsubhi.sa@gmail.com', '$2b$12$GHwofmEyataVf6OsglShsuJX1arYPyPSyf.7Gnuk1XnpZ.68sSIqO', '-----BEGIN CERTIFICATE-----\nMIICqjCCAZKgAwIBAgIUfaHweEIFtQjgiF4CEFzp0WmXqr8wDQYJKoZIhvcNAQEL\nBQAwDzENMAsGA1UEAwwETm9yYTAeFw0yNDExMzAxNDM5NTZaFw0yNTExMzAxNDM5\nNTZaMA8xDTALBgNVBAMMBE5vcmEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQDvvEIq2cMYj/Ky4+EKD0AgAi7dyrJVcMTvommVxZ+tWymjFodj6G9o857U\n2+Sd6l3JiGR9nGNSLMsK88LqKstM9k4gQeSknLmKB5RXsHnjuPL0caxk7DWTnPsv\nc6BXktY+b6pRlDmoePN/jFj6v7MY+1xSF2Ei7LmUIReLVZbpYfzO4Qaa1SYPJbIw\nxktt89ldLs4nRo2w40u0Qi+XH0WwBtCh5zJnn0N1naNhhGHOfQ5B912SCcyrVx12\nkokUuoH+DBYCDmesCDeq1YLiw9UdG9J99OLDfZ7JP8kk09FMzCHMjcp8WC1DwdiI\n4Su22kTJUDDV8NS2PXGgaivNF6C5AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGrL\n877poe6+p8mac/YOUN6Nw+woOFJRLdNjCmgUqSz8q4fsryPsU+I/Canl9wB/r4XZ\nyW58slAzPt7jzA6dIszQzFATCGXiftY2J8alVms0NST65GSsbvxhjMLBi/XXUaiQ\ncYWUvwF+iN245I6Y06FcIAt30WV4GKrnACcfhF9LaEP4kXSEZ+mjrZLr6LbLQ6IW\nBQy2XNxMXrenBkwF1uSYreubOhKDL4avCDb8YfGfFdLwe/3iJ7rVrLN6f9TaKFdq\ncIy1fvj/kpsIqUYL7Wo5KXyDWGyllFomm5rYEo12mg9NkIWHMeu3x3n68wr1lOgD\niKJBxBB8IOrG+v42t7k=\n-----END CERTIFICATE-----\n');

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
-- AUTO_INCREMENT for table `message`
--
ALTER TABLE `message`
  MODIFY `MessageID` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `user_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=132;

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
