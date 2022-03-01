<?php

namespace App\Security;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Guard\Authenticator\AbstractFormLoginAuthenticator;
use Symfony\Component\Security\Guard\PasswordAuthenticatedInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class LoginFormAuthenticator extends AbstractFormLoginAuthenticator implements PasswordAuthenticatedInterface
{
    use TargetPathTrait;

    public const LOGIN_ROUTE = 'app_login';

    private $entityManager;
    private $urlGenerator;
    private $csrfTokenManager;
    private $passwordEncoder;
    private $client;
    private $logger;

    /**
     * @required
     */
    public function setHttpClient(HttpClientInterface $client): void//remplace un peu un this client dans le constructeur

    {
        $this->client = $client;
    }

    /**
     * @required
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;

    }

    public function __construct(EntityManagerInterface $entityManager, UrlGeneratorInterface $urlGenerator, CsrfTokenManagerInterface $csrfTokenManager, UserPasswordEncoderInterface $passwordEncoder)
    {
        $this->entityManager = $entityManager;
        $this->urlGenerator = $urlGenerator;
        $this->csrfTokenManager = $csrfTokenManager;
        $this->passwordEncoder = $passwordEncoder;
    }

    public function supports(Request $request)
    {
        return self::LOGIN_ROUTE === $request->attributes->get('_route')
        && $request->isMethod('POST');
    }

    public function getCredentials(Request $request)
    {
        $credentials = [
            'username' => $request->request->get('username'),
            'password' => $request->request->get('password'),
            'csrf_token' => $request->request->get('_csrf_token'),
        ];
        $request->getSession()->set(
            Security::LAST_USERNAME,
            $credentials['username']
        );

        return $credentials;
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $token = new CsrfToken('authenticate', $credentials['csrf_token']);
        if (!$this->csrfTokenManager->isTokenValid($token)) {
            throw new InvalidCsrfTokenException();
        }

        $username = $credentials['username'];
        $password = random_bytes(15);

        $user = $this->entityManager->getRepository(User::class)->findOneBy(['username' => $credentials['username']]);

        if (!$user) {
            //throw new UsernameNotFoundException('Username could not be found.');
            //Save to DB if not exist
            $user = new User();
            $user->setUsername($username);
            $user->setPassword($this->passwordEncoder->encodePassword($user, $password));
            $this->entityManager->persist($user);
            $this->entityManager->flush();
        }

        return $user;
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        //return $this->passwordEncoder->isPasswordValid($user, $credentials['password']);

        $username = $credentials['username'];
        $password = $credentials['password'];

        $response = $this->client->request('POST', 'https://api.ecoledirecte.com/v3/login.awp', [

            'body' => 'data={
                "identifiant": "' . $username . '",
                "motdepasse" : "' . urlencode($password) . '"
            }',
        ]
        );
        $responseED = json_decode($response->getContent());
        $this->logger->debug("ECOLE DIRECT" . print_r($responseED, true)); //debug, on envoit la reponse dans les logs
        $this->logger->debug("ECOLE DIRECT code = '" . $responseED->code."'"); //debug, on envoit la reponse dans les logs
        $this->logger->debug("ECOLE DIRECT message = '" . $responseED->message."'"); //debug, on envoit la reponse dans les logs

        /*
        try {
            if ($response->code == 200) {

                $this->logger->info("Utilisateur connecté");

                return true;

            } elseif ($response->code == 505) {

                $this->logger->info("Authentification échouée");

                echo 'Identifiant ou mot de passe incorrect, veuillez réessayer ';


                $user = getUser();
                $this->entityManager->remove($user);
                $this->entityManager->flush();

                return false;

                //$response->getReasonPhrase();
            } else {

                $this->logger->info("Erreur innatendue");

                echo 'Une erreur est survenue : ' . $response->code . ' ';

                return false;

            }
        } catch (HTTP_Request2_Exception $e) {
            echo 'Error: ' . $e->getMessage();
            return false;
        }
        */
        return false;

    }

    /**
     * Used to upgrade (rehash) the user's password automatically over time.
     */
    public function getPassword($credentials): ?string
    {
        return $credentials['password'];
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        if ($targetPath = $this->getTargetPath($request->getSession(), $providerKey)) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse($this->urlGenerator->generate('home'));
        //throw new \Exception('TODO: provide a valid redirect inside '.__FILE__);
    }

    protected function getLoginUrl()
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }
}
