// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Portuguese (`pt`).
class AppLocalizationsPt extends AppLocalizations {
  AppLocalizationsPt([String locale = 'pt']) : super(locale);

  @override
  String get appTitle => 'DNA Connect';

  @override
  String get initializing => 'Inicializando...';

  @override
  String get failedToInitialize => 'Falha ao inicializar';

  @override
  String get makeSureNativeLibrary =>
      'Certifique-se de que a biblioteca nativa está disponível.';

  @override
  String get navHome => 'Início';

  @override
  String get navChats => 'Conversas';

  @override
  String get navWallet => 'Carteira';

  @override
  String get navMore => 'Mais';

  @override
  String get messagesAll => 'Todos';

  @override
  String get messagesUnread => 'Não lidos';

  @override
  String get messagesAllCaughtUp => 'Tudo em dia!';

  @override
  String get messagesNoUnread => 'Nenhuma mensagem não lida';

  @override
  String get messagesSearchHint => 'Pesquisar conversas...';

  @override
  String get contactsTitle => 'Contatos';

  @override
  String get contactsEmpty => 'Nenhum contato ainda';

  @override
  String get contactsTapToAdd => 'Toque em + para adicionar um contato';

  @override
  String get contactsOnline => 'Online';

  @override
  String contactsLastSeen(String time) {
    return 'Visto por último $time';
  }

  @override
  String get contactsOffline => 'Offline';

  @override
  String get contactsSyncing => 'Sincronizando...';

  @override
  String get contactsFailedToLoad => 'Falha ao carregar contatos';

  @override
  String get contactsRetry => 'Tentar novamente';

  @override
  String get contactsHubContacts => 'Contatos';

  @override
  String get contactsHubRequests => 'Solicitações';

  @override
  String get contactsHubBlocked => 'Bloqueados';

  @override
  String get contactsHubRemoveTitle => 'Remover Contato?';

  @override
  String contactsHubRemoveMessage(String name) {
    return 'Tem certeza que deseja remover $name dos seus contatos?';
  }

  @override
  String get contactsHubRemove => 'Remover';

  @override
  String get contactsHubFingerprintCopied => 'Impressão digital copiada';

  @override
  String get contactRequestsTitle => 'Solicitações de Contato';

  @override
  String get contactRequestsEmpty => 'Nenhuma solicitação pendente';

  @override
  String get contactRequestsAccept => 'Aceitar';

  @override
  String get contactRequestsDeny => 'Recusar';

  @override
  String get contactRequestsBlock => 'Bloquear Usuário';

  @override
  String get contactRequestsSent => 'Enviadas';

  @override
  String get contactRequestsReceived => 'Recebidas';

  @override
  String get addContactTitle => 'Adicionar Contato';

  @override
  String get addContactHint => 'Digite um nome ou ID';

  @override
  String get addContactSearching => 'Pesquisando...';

  @override
  String get addContactFoundOnNetwork => 'Encontrado na rede';

  @override
  String get addContactNotFound => 'Não encontrado';

  @override
  String get addContactSendRequest => 'Enviar Solicitação';

  @override
  String get addContactRequestSent => 'Solicitação de contato enviada';

  @override
  String get addContactAlreadyContact => 'Já está nos seus contatos';

  @override
  String get addContactCannotAddSelf => 'Você não pode adicionar a si mesmo';

  @override
  String get chatSearchMessages => 'Pesquisar mensagens';

  @override
  String get chatOnline => 'Online';

  @override
  String get chatOffline => 'Offline';

  @override
  String get chatConnecting => 'Conectando...';

  @override
  String get chatTypeMessage => 'Digite uma mensagem';

  @override
  String get chatNoMessages => 'Nenhuma mensagem ainda';

  @override
  String get chatSendFirstMessage =>
      'Envie uma mensagem para iniciar a conversa';

  @override
  String get chatPhotoLibrary => 'Biblioteca de Fotos';

  @override
  String get chatCamera => 'Câmera';

  @override
  String get chatAddCaption => 'Adicionar Legenda...';

  @override
  String get chatSendPhoto => 'Enviar';

  @override
  String chatImageTooLarge(String maxSize) {
    return 'Imagem muito grande (máx. $maxSize)';
  }

  @override
  String get chatMessageDeleted => 'Mensagem excluída';

  @override
  String get chatLoadEarlier => 'Carregar mensagens anteriores';

  @override
  String chatLastSeen(String time) {
    return 'Visto por último $time';
  }

  @override
  String get chatSendTokens => 'Enviar Tokens';

  @override
  String chatSendTokensTo(String name) {
    return 'para $name';
  }

  @override
  String get chatLookingUpWallets => 'Buscando endereços de carteira...';

  @override
  String get chatNoWalletAddresses =>
      'O contato não possui endereços de carteira no perfil';

  @override
  String get chatTokenLabel => 'Token';

  @override
  String get chatSendAmount => 'Valor';

  @override
  String chatSendAvailable(String balance, String token) {
    return 'Disponível: $balance $token';
  }

  @override
  String get chatSendMax => 'Máx';

  @override
  String chatSendButton(String token) {
    return 'Enviar $token';
  }

  @override
  String chatSentSuccess(String amount, String token) {
    return 'Enviado $amount $token';
  }

  @override
  String get chatInvalidAmount => 'Por favor, insira um valor válido';

  @override
  String chatInsufficientBalance(String token) {
    return 'Saldo insuficiente de $token';
  }

  @override
  String get chatNoWalletForNetwork =>
      'O contato não possui carteira para esta rede';

  @override
  String get chatSelectToken => 'Selecionar Token';

  @override
  String get chatSelectNetwork => 'Selecionar Rede';

  @override
  String get chatEnterAmount => 'Inserir Valor';

  @override
  String chatStepOf(String current, String total) {
    return 'Passo $current de $total';
  }

  @override
  String get messageMenuReply => 'Responder';

  @override
  String get messageMenuCopy => 'Copiar';

  @override
  String get messageMenuForward => 'Encaminhar';

  @override
  String get messageMenuStar => 'Favoritar';

  @override
  String get messageMenuUnstar => 'Desfavoritar';

  @override
  String get messageMenuRetry => 'Tentar novamente';

  @override
  String get messageMenuDelete => 'Excluir';

  @override
  String get groupsTitle => 'Grupos';

  @override
  String get groupsCreate => 'Criar Grupo';

  @override
  String get groupsEmpty => 'Nenhum grupo ainda';

  @override
  String get groupsCreateOrJoin => 'Crie um grupo ou aceite um convite';

  @override
  String get groupsPendingInvitations => 'Convites Pendentes';

  @override
  String get groupsYourGroups => 'Seus Grupos';

  @override
  String get groupsInfo => 'Informações do Grupo';

  @override
  String get groupsMembers => 'Membros';

  @override
  String get groupsLeave => 'Sair do Grupo';

  @override
  String get groupsDelete => 'Excluir Grupo';

  @override
  String get groupsInvite => 'Convidar';

  @override
  String get groupsAccept => 'Aceitar';

  @override
  String get groupsDecline => 'Recusar';

  @override
  String get groupsName => 'Nome do Grupo';

  @override
  String get groupsDescription => 'Descrição';

  @override
  String get groupsCreated => 'Grupo criado';

  @override
  String get groupsOwner => 'Proprietário';

  @override
  String get groupsMember => 'Membro';

  @override
  String get groupsAdmin => 'Administrador';

  @override
  String get groupsRemoveMember => 'Remover Membro';

  @override
  String groupsKickConfirm(String name) {
    return 'Remover $name do grupo?';
  }

  @override
  String get settingsTitle => 'Configurações';

  @override
  String get settingsAnonymous => 'Anônimo';

  @override
  String get settingsNotLoaded => 'Não carregado';

  @override
  String get settingsTapToEditProfile => 'Toque para editar o perfil';

  @override
  String get settingsAppearance => 'Aparência';

  @override
  String get settingsDarkMode => 'Modo Escuro';

  @override
  String get settingsDarkModeSubtitle => 'Alternar entre tema escuro e claro';

  @override
  String get settingsLanguage => 'Idioma';

  @override
  String get settingsLanguageSubtitle => 'Escolher idioma do aplicativo';

  @override
  String get settingsLanguageSystem => 'Padrão do sistema';

  @override
  String get settingsLanguageEnglish => 'English';

  @override
  String get settingsLanguageTurkish => 'Türkçe';

  @override
  String get settingsLanguageItalian => 'Italiano';

  @override
  String get settingsLanguageSpanish => 'Español';

  @override
  String get settingsLanguageRussian => 'Русский';

  @override
  String get settingsLanguageDutch => 'Nederlands';

  @override
  String get settingsLanguageGerman => 'Deutsch';

  @override
  String get settingsLanguageChinese => '中文';

  @override
  String get settingsLanguageJapanese => '日本語';

  @override
  String get settingsLanguagePortuguese => 'Português';

  @override
  String get settingsLanguageArabic => 'العربية';

  @override
  String get settingsBattery => 'Bateria';

  @override
  String get settingsDisableBatteryOpt => 'Desativar Otimização de Bateria';

  @override
  String get settingsBatteryChecking => 'Verificando...';

  @override
  String get settingsBatteryDisabled =>
      'Desativada — o aplicativo pode rodar em segundo plano';

  @override
  String get settingsBatteryTapToKeep =>
      'Toque para manter o aplicativo ativo em segundo plano';

  @override
  String get settingsSecurity => 'Segurança';

  @override
  String get settingsExportSeedPhrase => 'Exportar Frase de Recuperação';

  @override
  String get settingsExportSeedSubtitle =>
      'Faça backup da sua frase de recuperação';

  @override
  String get settingsAppLock => 'Bloqueio do App';

  @override
  String get settingsAppLockSubtitle => 'Exigir autenticação';

  @override
  String get settingsExportSeedWarning =>
      'Sua frase de recuperação concede acesso total à sua identidade. Nunca a compartilhe com ninguém.';

  @override
  String get settingsShowSeed => 'Mostrar Frase';

  @override
  String get settingsYourSeedPhrase => 'Sua Frase de Recuperação';

  @override
  String get settingsSeedPhraseWarning =>
      'Escreva estas palavras em ordem e guarde-as em segurança. Qualquer pessoa com esta frase pode acessar sua identidade.';

  @override
  String get settingsSeedCopied =>
      'Frase de recuperação copiada para a área de transferência';

  @override
  String get settingsSeedNotAvailable =>
      'Frase de recuperação não disponível para esta identidade. Ela foi criada antes desta funcionalidade ser adicionada.';

  @override
  String get settingsSeedError =>
      'Não foi possível recuperar a frase de recuperação';

  @override
  String get settingsWallet => 'Carteira';

  @override
  String get settingsHideZeroBalance => 'Ocultar Saldo Zero';

  @override
  String get settingsHideZeroBalanceSubtitle => 'Ocultar moedas com saldo zero';

  @override
  String get settingsData => 'Dados';

  @override
  String get settingsAutoSync => 'Sincronização Automática';

  @override
  String get settingsAutoSyncSubtitle =>
      'Sincronizar mensagens automaticamente a cada 15 minutos';

  @override
  String settingsLastSync(String time) {
    return 'Última sincronização: $time';
  }

  @override
  String get settingsSyncNow => 'Sincronizar Agora';

  @override
  String get settingsSyncNowSubtitle => 'Forçar sincronização imediata';

  @override
  String get settingsLogs => 'Registros';

  @override
  String get settingsOpenLogsFolder => 'Abrir Pasta de Registros';

  @override
  String get settingsOpenLogsFolderSubtitle =>
      'Abrir gerenciador de arquivos na pasta de registros';

  @override
  String get settingsShareLogs => 'Compartilhar Registros';

  @override
  String get settingsShareLogsSubtitle =>
      'Compactar e compartilhar arquivos de registro';

  @override
  String get settingsLogsFolderNotExist =>
      'A pasta de registros ainda não existe';

  @override
  String get settingsNoLogFiles => 'Nenhum arquivo de registro encontrado';

  @override
  String get settingsFailedCreateZip => 'Falha ao criar arquivo zip';

  @override
  String settingsNoLogsYet(String debugInfo) {
    return 'Nenhum registro ainda. $debugInfo';
  }

  @override
  String get settingsIdentity => 'Identidade';

  @override
  String get settingsFingerprint => 'Impressão Digital';

  @override
  String get settingsFingerprintCopied => 'Impressão digital copiada';

  @override
  String get settingsDeleteAccount => 'Excluir Conta';

  @override
  String get settingsDeleteAccountSubtitle =>
      'Excluir permanentemente todos os dados do dispositivo';

  @override
  String get settingsDeleteAccountConfirm => 'Excluir Conta?';

  @override
  String get settingsDeleteAccountWarning =>
      'Isso excluirá permanentemente todos os dados locais:';

  @override
  String get settingsDeletePrivateKeys => 'Chaves privadas';

  @override
  String get settingsDeleteWallets => 'Carteiras';

  @override
  String get settingsDeleteMessages => 'Mensagens';

  @override
  String get settingsDeleteContacts => 'Contatos';

  @override
  String get settingsDeleteGroups => 'Grupos';

  @override
  String get settingsDeleteSeedWarning =>
      'Certifique-se de ter feito backup da sua frase de recuperação antes de excluir!';

  @override
  String get settingsDeleteSuccess => 'Conta excluída com sucesso';

  @override
  String settingsDeleteFailed(String error) {
    return 'Falha ao excluir conta: $error';
  }

  @override
  String get settingsAbout => 'Sobre';

  @override
  String get settingsUpdateAvailable => 'Atualização Disponível';

  @override
  String get settingsTapToDownload => 'Toque para baixar';

  @override
  String settingsAppVersion(String version) {
    return 'DNA Connect v$version';
  }

  @override
  String settingsLibVersion(String version) {
    return 'Biblioteca v$version';
  }

  @override
  String get settingsPostQuantumMessenger =>
      'Comunicação com Criptografia Pós-Quântica';

  @override
  String get settingsCryptoStack => 'STACK CRIPTOGRÁFICO';

  @override
  String get profileTitle => 'Editar Perfil';

  @override
  String get profileInfo => 'Informações do Perfil';

  @override
  String get profileBio => 'Bio';

  @override
  String get profileLocation => 'Localização';

  @override
  String get profileWebsite => 'Site';

  @override
  String get profileWalletAddresses => 'Endereços de Carteira';

  @override
  String get profileSave => 'Salvar Perfil';

  @override
  String get profileShareQR => 'Compartilhar Meu QR Code';

  @override
  String get profileAvatar => 'Avatar';

  @override
  String get profileTakeSelfie => 'Tirar uma Selfie';

  @override
  String get profileChooseFromGallery => 'Escolher da Galeria';

  @override
  String get profileSaved => 'Perfil salvo';

  @override
  String profileSaveFailed(String error) {
    return 'Falha ao salvar perfil: $error';
  }

  @override
  String get profileCropTitle => 'Recortar Avatar';

  @override
  String get profileCropSave => 'Salvar';

  @override
  String get contactProfileFailed => 'Falha ao carregar perfil';

  @override
  String get contactProfileUnknownError => 'Erro desconhecido';

  @override
  String get contactProfileNickname => 'Apelido';

  @override
  String get contactProfileNicknameNotSet =>
      'Não definido (toque para adicionar)';

  @override
  String contactProfileOriginal(String name) {
    return 'Original: $name';
  }

  @override
  String get contactProfileSetNickname => 'Definir Apelido';

  @override
  String contactProfileOriginalName(String name) {
    return 'Nome original: $name';
  }

  @override
  String get contactProfileNicknameLabel => 'Apelido';

  @override
  String get contactProfileNicknameHint => 'Digite um apelido personalizado';

  @override
  String get contactProfileNicknameHelper =>
      'Deixe vazio para usar o nome original';

  @override
  String get contactProfileNicknameCleared => 'Apelido removido';

  @override
  String contactProfileNicknameSet(String name) {
    return 'Apelido definido como \"$name\"';
  }

  @override
  String contactProfileNicknameFailed(String error) {
    return 'Falha ao definir apelido: $error';
  }

  @override
  String get contactProfileCopyFingerprint => 'Copiar impressão digital';

  @override
  String get contactProfileNoProfile => 'Nenhum perfil publicado';

  @override
  String get contactProfileNoProfileSubtitle =>
      'Este usuário ainda não publicou seu perfil.';

  @override
  String get contactProfileBio => 'Bio';

  @override
  String get contactProfileInfo => 'Informações';

  @override
  String get contactProfileWebsite => 'Site';

  @override
  String get identityTitle => 'DNA Connect';

  @override
  String get identityWelcome => 'Bem-vindo ao DNA Connect';

  @override
  String get identityGenerateSeed => 'Gerar Nova Frase';

  @override
  String get identityHaveSeed => 'Já Tenho uma Frase de Recuperação';

  @override
  String get identityYourRecoveryPhrase => 'Sua Frase de Recuperação';

  @override
  String get identityRecoveryPhraseWarning =>
      'Anote estas palavras e guarde-as em segurança. Elas são a única forma de recuperar sua conta.';

  @override
  String get identityConfirmSaved => 'Salvei minha frase de recuperação';

  @override
  String get identityEnterRecoveryPhrase => 'Inserir Frase de Recuperação';

  @override
  String get identityEnterRecoveryPhraseHint =>
      'Digite sua frase de recuperação de 12 ou 24 palavras';

  @override
  String get identityChooseName => 'Escolha Seu Nome';

  @override
  String get identityChooseNameHint => 'Digite um nome de exibição';

  @override
  String get identityRegisterContinue => 'Registrar & Continuar';

  @override
  String get identityRegistering => 'Registrando...';

  @override
  String get identityNameTaken => 'Este nome já está em uso';

  @override
  String get identityNameInvalid => 'O nome deve ter entre 3 e 20 caracteres';

  @override
  String get identityCreating => 'Criando sua identidade...';

  @override
  String get identityRestoring => 'Restaurando sua identidade...';

  @override
  String get wallTitle => 'Início';

  @override
  String get wallWelcome => 'Bem-vindo ao seu feed!';

  @override
  String get wallWelcomeSubtitle =>
      'Siga pessoas e canais para ver as publicações deles aqui.';

  @override
  String get wallNewPost => 'Nova Publicação';

  @override
  String get wallDeletePost => 'Excluir Publicação';

  @override
  String get wallDeletePostConfirm =>
      'Tem certeza que deseja excluir esta publicação?';

  @override
  String get wallRepost => 'Repostar';

  @override
  String get wallReposted => 'Repostado';

  @override
  String get wallComments => 'Comentários';

  @override
  String get wallNoComments => 'Nenhum comentário ainda';

  @override
  String get wallLoadingComments => 'Carregando comentários...';

  @override
  String get wallWriteComment => 'Escrever um comentário...';

  @override
  String get wallWriteReply => 'Escrever uma resposta...';

  @override
  String wallViewAllComments(int count) {
    return 'Ver todos os $count comentários';
  }

  @override
  String get wallPostDetail => 'Publicação';

  @override
  String get wallCopy => 'Copiar';

  @override
  String get wallReply => 'Responder';

  @override
  String get wallDelete => 'Excluir';

  @override
  String get wallBlockUser => 'Block User';

  @override
  String wallBlockUserConfirm(String name) {
    return 'Block $name? You will no longer see their posts or messages.';
  }

  @override
  String wallUserBlocked(String name) {
    return '$name has been blocked';
  }

  @override
  String get wallSendContactRequest => 'Send Contact Request';

  @override
  String wallContactRequestSent(String name) {
    return 'Contact request sent to $name';
  }

  @override
  String get wallContactRequestMessage => 'Message (optional)';

  @override
  String get wallUnfriend => 'Remove from Contacts';

  @override
  String wallUnfriendConfirm(String name) {
    return 'Remove $name from your contacts?';
  }

  @override
  String wallUnfriended(String name) {
    return '$name removed from contacts';
  }

  @override
  String get wallFollow => 'Follow';

  @override
  String get wallUnfollow => 'Unfollow';

  @override
  String wallFollowed(String name) {
    return 'Now following $name';
  }

  @override
  String wallUnfollowed(String name) {
    return 'Unfollowed $name';
  }

  @override
  String get wallTip => 'Gorjeta';

  @override
  String get wallTipTitle => 'Dar gorjeta nesta publicação';

  @override
  String wallTipAmount(String amount) {
    return '$amount CPUNK';
  }

  @override
  String get wallTipConfirm => 'Enviar gorjeta';

  @override
  String get wallTipCancel => 'Cancelar';

  @override
  String get wallTipSuccess => 'Gorjeta enviada!';

  @override
  String wallTipFailed(String error) {
    return 'Gorjeta falhou: $error';
  }

  @override
  String get wallTipNoWallet =>
      'Este usuário não tem endereço de carteira no perfil';

  @override
  String get wallTipInsufficientBalance => 'Saldo CPUNK insuficiente';

  @override
  String get wallTipSending => 'Enviando gorjeta...';

  @override
  String wallTippedAmount(String amount) {
    return '$amount CPUNK de gorjeta';
  }

  @override
  String get wallTipPending => 'Pendente';

  @override
  String get wallTipVerified => 'Verificado';

  @override
  String get wallTipFailedStatus => 'Falhou';

  @override
  String get wallWhatsOnYourMind => 'No que você está pensando?';

  @override
  String get wallPost => 'Publicar';

  @override
  String get wallPosting => 'Publicando...';

  @override
  String get wallUploadingImage => 'Uploading...';

  @override
  String get wallBoost => 'Boost';

  @override
  String get wallBoostDescription => 'Compartilhar com todos';

  @override
  String get wallBoosted => 'Boosted';

  @override
  String get wallBoostLimitReached => 'Limite diário de boost atingido';

  @override
  String get wallAddComment => 'Adicionar um comentário (opcional)';

  @override
  String get wallCreatePostTitle => 'Criar Publicação';

  @override
  String get walletTitle => 'Carteira';

  @override
  String get walletTotalBalance => 'Saldo Total';

  @override
  String get walletSend => 'Enviar';

  @override
  String get walletReceive => 'Receber';

  @override
  String get walletSwap => 'Trocar';

  @override
  String get walletHistory => 'Histórico';

  @override
  String get walletNoTransactions => 'Nenhuma transação ainda';

  @override
  String get walletCopyAddress => 'Copiar Endereço';

  @override
  String get walletAddressCopied => 'Endereço copiado';

  @override
  String walletSendTitle(String coin) {
    return 'Enviar $coin';
  }

  @override
  String get walletRecipientAddress => 'Endereço do Destinatário';

  @override
  String get walletAmount => 'Valor';

  @override
  String get walletMax => 'MÁX';

  @override
  String get walletSendConfirm => 'Confirmar Envio';

  @override
  String get walletSending => 'Enviando...';

  @override
  String get walletSendSuccess => 'Transação enviada';

  @override
  String walletSendFailed(String error) {
    return 'Transação falhou: $error';
  }

  @override
  String walletReceiveTitle(String coin) {
    return 'Receber $coin';
  }

  @override
  String get walletAddressBook => 'Agenda de Endereços';

  @override
  String get walletAddAddress => 'Adicionar Endereço';

  @override
  String get walletEditAddress => 'Editar Endereço';

  @override
  String get walletDeleteAddress => 'Excluir Endereço';

  @override
  String get walletLabel => 'Rótulo';

  @override
  String get walletAddress => 'Endereço';

  @override
  String get walletNetwork => 'Rede';

  @override
  String get qrScannerTitle => 'Scanner de QR';

  @override
  String get qrAddContact => 'Adicionar Contato';

  @override
  String get qrAuthRequest => 'Solicitação de Autorização';

  @override
  String get qrContent => 'Conteúdo do QR';

  @override
  String get qrSendContactRequest => 'Enviar Solicitação de Contato';

  @override
  String get qrScanAnother => 'Escanear Outro';

  @override
  String get qrCopyFingerprint => 'Copiar';

  @override
  String get qrRequestSent => 'Solicitação de contato enviada';

  @override
  String get qrInvalidCode => 'Código QR inválido';

  @override
  String get moreTitle => 'Mais';

  @override
  String get moreWallet => 'Carteira';

  @override
  String get moreQRScanner => 'Scanner de QR';

  @override
  String get moreAddresses => 'Endereços';

  @override
  String get moreStarred => 'Favoritos';

  @override
  String get moreContacts => 'Contatos';

  @override
  String get moreSettings => 'Configurações';

  @override
  String get moreAppLock => 'Bloqueio do App';

  @override
  String get moreInviteFriends => 'Convidar amigos';

  @override
  String inviteFriendsMessage(String username) {
    return 'Olá! Experimente o DNA Connect — um mensageiro criptografado à prova de quantum. Me adicione: $username — Baixe: https://cpunk.io/download';
  }

  @override
  String get lockTitle => 'DNA Connect';

  @override
  String get lockEnterPIN => 'Digite o PIN para desbloquear';

  @override
  String get lockIncorrectPIN => 'PIN incorreto';

  @override
  String lockTooManyAttempts(int seconds) {
    return 'Muitas tentativas. Tente novamente em ${seconds}s';
  }

  @override
  String get lockUseBiometrics => 'Usar biometria para desbloquear';

  @override
  String get appLockTitle => 'Bloqueio do App';

  @override
  String get appLockEnable => 'Ativar Bloqueio do App';

  @override
  String get appLockUseBiometrics => 'Usar Biometria';

  @override
  String get appLockChangePIN => 'Alterar PIN';

  @override
  String get appLockSetPIN => 'Definir PIN';

  @override
  String get appLockConfirmPIN => 'Confirmar PIN';

  @override
  String get appLockPINMismatch => 'Os PINs não coincidem';

  @override
  String get appLockPINSet => 'PIN definido com sucesso';

  @override
  String get appLockPINChanged => 'PIN alterado';

  @override
  String get appLockEnterCurrentPIN => 'Digite o PIN atual';

  @override
  String get appLockEnterNewPIN => 'Digite o novo PIN';

  @override
  String get starredTitle => 'Mensagens Favoritas';

  @override
  String get starredEmpty => 'Nenhuma mensagem favorita';

  @override
  String get blockedTitle => 'Usuários Bloqueados';

  @override
  String get blockedEmpty => 'Nenhum usuário bloqueado';

  @override
  String get blockedUnblock => 'Desbloquear';

  @override
  String blockedUnblockConfirm(String name) {
    return 'Desbloquear $name?';
  }

  @override
  String get updateTitle => 'Atualização Necessária';

  @override
  String get updateMessage =>
      'Uma versão mais recente é necessária para continuar usando o DNA Connect.';

  @override
  String get updateDownload => 'Baixar Atualização';

  @override
  String get updateAvailableTitle => 'Nova Versão Disponível';

  @override
  String get updateAvailableMessage =>
      'Uma nova versão do DNA Connect está disponível. Atualize agora para obter os recursos e melhorias mais recentes.';

  @override
  String get updateLater => 'Depois';

  @override
  String get cancel => 'Cancelar';

  @override
  String get save => 'Salvar';

  @override
  String get delete => 'Excluir';

  @override
  String get done => 'Concluído';

  @override
  String get copy => 'Copiar';

  @override
  String get ok => 'OK';

  @override
  String get yes => 'Sim';

  @override
  String get no => 'Não';

  @override
  String get error => 'Erro';

  @override
  String get success => 'Sucesso';

  @override
  String get loading => 'Carregando...';

  @override
  String get pleaseWait => 'Por favor, aguarde...';

  @override
  String get copied => 'Copiado';

  @override
  String failed(String error) {
    return 'Falhou: $error';
  }

  @override
  String get retry => 'Tentar novamente';

  @override
  String get continueButton => 'Continuar';

  @override
  String get approve => 'Aprovar';

  @override
  String get deny => 'Recusar';

  @override
  String get verify => 'Verificar';

  @override
  String get copyToClipboard => 'Copiar para a Área de Transferência';

  @override
  String get copiedToClipboard => 'Copiado para a área de transferência';

  @override
  String get pasteFromClipboard => 'Colar da Área de Transferência';

  @override
  String get biometricsSubtitle => 'Impressão digital ou Face ID';

  @override
  String get changePINSubtitle => 'Atualizar seu PIN de desbloqueio';

  @override
  String get biometricFailed => 'Autenticação biométrica falhou';

  @override
  String get contactRequestsWillAppear =>
      'Solicitações de contato aparecerão aqui';

  @override
  String get blockedUsersWillAppear =>
      'Usuários que você bloquear aparecerão aqui';

  @override
  String get failedToLoadTimeline => 'Falha ao carregar o feed';

  @override
  String get userUnblocked => 'Usuário desbloqueado';

  @override
  String get backupFound => 'Backup Encontrado';

  @override
  String approvedContact(String name) {
    return 'Aprovado $name';
  }

  @override
  String deniedContact(String name) {
    return 'Recusado $name';
  }

  @override
  String blockedContact(String name) {
    return 'Bloqueado $name';
  }

  @override
  String unsubscribeFrom(String name) {
    return 'Cancelar inscrição de $name';
  }

  @override
  String get chatSenderDeletedThis => 'O remetente excluiu esta mensagem';

  @override
  String get chatDeleteMessageTitle => 'Excluir Mensagem';

  @override
  String get chatDeleteMessageConfirm =>
      'Excluir esta mensagem de todos os seus dispositivos e notificar a outra pessoa?';

  @override
  String get chatDeleteConversation => 'Excluir Conversa';

  @override
  String get chatDeleteConversationTitle => 'Excluir Conversa';

  @override
  String get chatDeleteConversationConfirm =>
      'Excluir todas as mensagens desta conversa? Isso excluirá de todos os seus dispositivos.';

  @override
  String get chatConversationDeleted => 'Conversa excluída';

  @override
  String get chatDeleteConversationFailed => 'Falha ao excluir conversa';

  @override
  String get settingsDeleteAllMessages => 'Excluir Todas as Mensagens';

  @override
  String get settingsDeleteAllMessagesSubtitle =>
      'Remover todas as mensagens de todos os dispositivos';

  @override
  String get settingsDeleteAllMessagesTitle => 'Excluir Todas as Mensagens?';

  @override
  String get settingsDeleteAllMessagesWarning =>
      'Isso excluirá permanentemente TODAS as mensagens de TODAS as conversas em todos os seus dispositivos. Esta ação não pode ser desfeita.';

  @override
  String get settingsAllMessagesDeleted => 'Todas as mensagens excluídas';

  @override
  String get settingsDeleteAllMessagesFailed => 'Falha ao excluir mensagens';

  @override
  String get settingsDeleteEverything => 'Excluir Tudo';

  @override
  String get txDetailSent => 'Enviado';

  @override
  String get txDetailReceived => 'Recebido';

  @override
  String get txDetailDenied => 'Transação Recusada';

  @override
  String get txDetailFrom => 'De';

  @override
  String get txDetailTo => 'Para';

  @override
  String get txDetailTransactionHash => 'Hash da Transação';

  @override
  String get txDetailTime => 'Hora';

  @override
  String get txDetailNetwork => 'Rede';

  @override
  String get txDetailAddressCopied => 'Endereço copiado';

  @override
  String get txDetailHashCopied => 'Hash copiado';

  @override
  String get txDetailAddToAddressBook => 'Adicionar à Agenda';

  @override
  String get txDetailClose => 'Fechar';

  @override
  String txDetailAddedToAddressBook(String label) {
    return 'Adicionado \"$label\" à agenda';
  }

  @override
  String txDetailFailedToAdd(String error) {
    return 'Falha ao adicionar: $error';
  }

  @override
  String get swapTitle => 'Trocar';

  @override
  String get swapConfirm => 'Confirmar Troca';

  @override
  String get swapYouPay => 'Você paga';

  @override
  String get swapYouReceive => 'Você recebe';

  @override
  String get swapGetQuote => 'Obter Cotação';

  @override
  String get swapNoQuotes => 'Nenhuma cotação disponível';

  @override
  String get swapRate => 'Taxa';

  @override
  String get swapSlippage => 'Deslizamento';

  @override
  String get swapFee => 'Taxa';

  @override
  String get swapDex => 'DEX';

  @override
  String swapImpact(String value) {
    return 'Impacto: $value%';
  }

  @override
  String swapFeeValue(String value) {
    return 'Taxa: $value';
  }

  @override
  String swapBestPrice(int count) {
    return 'Melhor preço de $count exchanges';
  }

  @override
  String swapSuccess(
    String amountIn,
    String fromToken,
    String amountOut,
    String toToken,
    String dex,
  ) {
    return 'Trocado $amountIn $fromToken → $amountOut $toToken via $dex';
  }

  @override
  String swapFailed(String error) {
    return 'Troca falhou: $error';
  }

  @override
  String get chatDownloadingMedia => 'Downloading...';

  @override
  String get chatUploadFailed => 'Upload failed. Tap to retry.';

  @override
  String get chatTapToDownload => 'Tap to download';

  @override
  String get chatVideoComingSoon => 'Video playback coming soon';

  @override
  String get chatAudioComingSoon => 'Audio playback coming soon';

  @override
  String get chatMediaUnsupported => 'Unsupported media type';
}
