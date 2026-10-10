# A build-artifact check, not a source-string assertion or a hardware test.
execute_process(COMMAND "${NM}" -C "${EXE}"
                OUTPUT_VARIABLE symbols ERROR_VARIABLE error RESULT_VARIABLE status)
if(NOT status EQUAL 0)
    message(FATAL_ERROR "nm failed: ${error}")
endif()
if(symbols MATCHES "kguard::field::presence_v2|VL53L1X|::detector")
    message(FATAL_ERROR "non-ToF field target retained a detector or sensor symbol")
endif()
message(STATUS "non-ToF artifact has no KG detector, sample/transition owner, or VL53L1X symbols")
