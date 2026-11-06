package com.example.multichain;

interface LoginAttemptCounter {

    Long increment(String clientIp);
}
