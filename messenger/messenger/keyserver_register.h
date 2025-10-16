/*
 * Keyserver Registration
 */

#ifndef KEYSERVER_REGISTER_H
#define KEYSERVER_REGISTER_H

/**
 * Register current user to keyserver
 *
 * @param identity: User's DNA identity
 * @return: 0 on success, -1 on error
 */
int register_to_keyserver(const char *identity);

#endif // KEYSERVER_REGISTER_H
