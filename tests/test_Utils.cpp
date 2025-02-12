// tests/test_Utils.cpp
#include <gtest/gtest.h>
#include "../src/Utils.h"

TEST(UtilsTest, GetCurrentTimestampFormat) {
    std::string timestamp = Utils::getCurrentTimestamp();
    // Expected format: "YYYY-MM-DD HH:MM:SS" (19 characters)
    EXPECT_EQ(timestamp.size(), 19);
}

TEST(UtilsTest, LogEventDoesNotThrow) {
    // Ensure that calling logEvent does not throw any exceptions.
    EXPECT_NO_THROW(Utils::logEvent("Test log event", LogLevel::INFO));
}