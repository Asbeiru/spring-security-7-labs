package com.zhouzhou.agent.web;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.zhouzhou.agent.tools.VaultAgentTools;

@RestController
public class AgentController {

    private final ChatClient chatClient;

    public AgentController(ChatClient.Builder chatClientBuilder, VaultAgentTools vaultAgentTools) {
        this.chatClient = chatClientBuilder
                .defaultSystem("你是企业资产助手。任何工具的授权结果以系统返回为准，不要尝试绕过。")
                .defaultTools(vaultAgentTools)
                .build();
    }

    @PostMapping("/agent/chat")
    public String chat(@RequestBody String message) {
        return this.chatClient.prompt().user(message).call().content();
    }
}
