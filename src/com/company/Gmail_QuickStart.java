// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// [START gmail_quickstart]
package com.company;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.GmailScopes;
import com.google.api.services.gmail.model.Label;
import com.google.api.services.gmail.model.ListLabelsResponse;
import com.google.api.services.gmail.model.ListMessagesResponse;
import com.google.api.services.gmail.model.Message;

import javax.mail.MessageAware;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Gmail_QuickStart {
    private static final String APPLICATION_NAME = "Gmail API";
    private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
    private static final String TOKENS_DIRECTORY_PATH = "tokens";
    private static final List<String> labels = new ArrayList<String>();
    private static final ArrayList<String> messages = new ArrayList<>();
    private static String userID = "";

    /**
     * Global instance of the scopes required by this quickstart.
     * If modifying these scopes, delete your previously saved tokens/ folder.
     *
     */
    private static final List<String> SCOPES = Arrays.asList(GmailScopes.MAIL_GOOGLE_COM);
    private static final String CREDENTIALS_FILE_PATH = "credentials";

    /**
     * Create a new API instance after we put in the userID email address.
     */

    public Gmail_QuickStart(String uID) throws IOException, GeneralSecurityException {
        userID = uID;
        runAPI();
    }

    /**
     * Creates an authorized Credential object.
     * @param HTTP_TRANSPORT The network HTTP Transport.
     * @return An authorized Credential object.
     * @throws IOException If the credentials.json file cannot be found.
     */
    private static Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT) throws IOException {
        // Load client secrets.
        InputStream in = Gmail_QuickStart.class.getResourceAsStream(CREDENTIALS_FILE_PATH);
        GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(in));

        // Build flow and trigger user authorization request.
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, SCOPES)
                .setDataStoreFactory(new FileDataStoreFactory(new java.io.File(TOKENS_DIRECTORY_PATH)))
                .setAccessType("offline")
                .build();
        LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(9999).build();
        return new AuthorizationCodeInstalledApp(flow, receiver).authorize(userID);
    }

    public void runAPI() throws IOException, GeneralSecurityException {
        // Build a new authorized API client service.
        final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
        Gmail service = new Gmail.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT))
                .setApplicationName(APPLICATION_NAME)
                .build();

        ListLabelsResponse listResponse = service.users().labels().list(userID).execute();
        //Get our Labels.
        List<Label> ourLabels = listResponse.getLabels();
        List<String> l = new ArrayList<>();
        //Find the label we need, which is the "unread" label.
        if (!ourLabels.isEmpty()) {
            for (Label label : ourLabels) {
                if (label.getName().contains("UNREAD")) {
                    labels.add(label.getId());
                }
            }
        }
        List<Message> messageIDs = listMessagesWithLabels(service, userID, labels);
        for (Message msg: messageIDs) {
            messages.add(getMessage(service, userID, msg.getThreadId()));

        }
    }

    public static void getOurMessages() {
        for (String m: messages) {
            System.out.println(m);
        }
    }

    /**
     * List all Messages of the user's mailbox with labelIds applied.
     *
     * @param service Authorized Gmail API instance.
     * @param userId User's email address. The special value "me"
     * can be used to indicate the authenticated user.
     * @param labelIds Only return Messages with these labelIds applied.
     * @throws IOException If messages can not be found with the desired labels.
     */
    public static List<Message> listMessagesWithLabels(Gmail service, String userId,
                                                       List<String> labelIds) throws IOException {
        ListMessagesResponse response = service.users().messages().list(userId)
                .setLabelIds(labelIds).execute();

        List<Message> messages = new ArrayList<>();
        while (response.getMessages() != null) {
            messages.addAll(response.getMessages());
            if (response.getNextPageToken() != null) {
                String pageToken = response.getNextPageToken();
                response = service.users().messages().list(userId).setLabelIds(labelIds)
                        .setPageToken(pageToken).execute();
            } else {
                break;
            }
        }

//        for (Message message : messages) {
//            System.out.println(message.toPrettyString());
//        }

        return messages;
    }

    /**
     * Returns the message at the specific ID.
     * @param service The service.
     * @param userId The email address
     * @param messageId The id of the specific message.
     * @throws IOException If the message isn't there with the threadID.
     */

    public static String getMessage(Gmail service, String userId, String messageId)
            throws IOException {
        Message message = service.users().messages().get(userId, messageId).execute();

        return "Message snippet: " + message.getSnippet();
    }
}

