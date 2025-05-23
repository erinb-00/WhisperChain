from google import genai
from google.genai import types

client = genai.Client(api_key="AIzaSyAPc_aG5yR8YGwEmFKTTa2PmRAw6h_SY0w")

messages = [
    "Hope your day is going well.",
    "You're worthless and a waste of space.",
    "I disagree with your take, but I respect your opinion.",
    "Can we please keep the conversation civil? I’d like to have a productive discussion.",
    "Go kill yourself, nobody wants you here.",
    "You're such an idiot, how do you not understand that?",
    "Thanks for your help earlier, that really made a difference!",
    "Why don't you go cry to your mommy, loser?",
    "I’m gonna find out where you live if you don’t stop.",
    "Could you explain that a bit more? I'm trying to understand.",
    "Nice profile picture! Did you take that photo yourself?",
    "Great game! Let's play again sometime.",
    "Stop talking, no one wants to hear your stupid voice.",
    "You're just a [expletive], get out of here.",
    "I don't agree with your point, but I see where you're coming from.",
    "Typical [slur], always playing the victim.",
    "You're the worst player on this team, uninstall the game.",
    "Hey, are you free to chat later? I have a quick question.",
    "No one cares about your dumb opinion, just shut up.",
    "Sorry if I came off rude earlier. That wasn't my intention."
]

# The following function uses the Gemini model to classify messages as abusive or not
# Recommended temperature is 0.5 for this task
# using gemini 2.0 flash lite model for fast inference
def gemini_agent(message):
    response = client.models.generate_content(
        model="gemini-2.0-flash-lite",
        config=types.GenerateContentConfig(
            system_instruction="You are a moderator for a secure, anonymous chat application. Your job is to determine if the following message is abusive or not.",
            max_output_tokens=10,
            temperature=0.5 ),
        contents = f"Respond 'true' if the following message is using abusive language, 'false' if not. Message: {message}"
        )
    return response.text


# Test the Gemini agent with a few messages (usually free tier only allows 14 messages at a time)
print("Gemini Agent Responses:")
for message in messages:
    response = gemini_agent(message)
    print(f"Message: {message}\nResponse: {response}\n")