var Q = require('q');
var express = require('express');
var bodyParser = require('body-parser');
var GithubAPI = require('github');
var crypto = require('crypto');
var ipFilter = require('express-ipfilter').IpFilter;

var requiredApprovalCount = parseInt(process.env.REQUIRED_APPROVAL_COUNT);

var github = new GithubAPI({
  debug: false,
  protocol: 'https',
  host: 'api.github.com',
  headers: {
    'user-agent': 'krush-review'
  },
  Promise: Q.Promise,
  timeout: 5000
});

var verifyHmac = (req, res, buf) => {
  var providedSignature = req.get('X-Hub-Signature');

  if (providedSignature) {
    // then calculate HMAC-SHA1 on the content.
    var hmac = crypto.createHmac('sha1', process.env.GITHUB_WEBHOOK_SECRET);
    hmac.update(buf);
    var calculatedSignature = 'sha1=' + hmac.digest(encoding = 'hex');

    if (providedSignature != calculatedSignature) {
      console.log(
        'Wrong signature - providedSignature: %s, calculatedSignature: %s',
        providedSignature,
        calculatedSignature);
      var error = {
        status: 400,
        body: 'Wrong signature'
      };
      throw error;
    }
  }
};

var oauthToken = process.env.GITHUB_ACCESS_TOKEN;

var app = express();

app.set('port', (process.env.PORT || 5000));

var ips = [process.env.GITHUB_ALLOWED_IPS];

var verifyIp = ipFilter(ips, {
  mode: 'allow',
  allowedHeaders: ['x-forwarded-for']
});
var parseJsonWithHmac = bodyParser.json({
  verify: verifyHmac
});
app.use(express.static(__dirname + '/public'));

// views is directory for all template files
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

var Webhook = {
  PullRequest: {
    process: (payload) => {
      switch (payload.action) {
        case 'opened':
          return Webhook.PullRequest.processOpened(payload);

        case 'synchronize':
          return Webhook.PullRequest.processSynchronized(payload);

        default:
          return Q(true);
      }
    },
    processOpened: (payload) => {
      var pullRequest = payload.pull_request;
      var repository = payload.repository;
      var organization = payload.organization;
      var sender = payload.sender;

      return Repository.applyApprovalStatus(repository, pullRequest);
    },
    processSynchronized: (payload) => {
      var pullRequest = payload.pull_request;
      var repository = payload.repository;
      var organization = payload.organization;
      var sender = payload.sender;
      var previousHead = payload.before;
      var newHead = payload.after;

      return PullRequest.getAllReviews(
        repository.owner.login,
        repository.name,
        pullRequest.number
      ).then((reviews) => {
        var promises = [];
        for (const review of reviews) {
          switch (review.state) {
            case "CHANGES_REQUESTED":
            case "APPROVED":
              promises.push(PullRequest.dismissReview(repository, pullRequest, review, 'New commit pushed'));
              break;
            default:
              break;
          }
        }
        return Q.all(promises);
      }).then(() => {
        return Repository.applyApprovalStatus(repository, pullRequest);
      });
    }
  },
  PullRequestReview: {
    process: (payload) => {
      switch (payload.action) {
        case 'submitted':
          return Webhook.PullRequestReview.processSubmitted(payload);

        default:
          return Q(true);
      }
    },
    processSubmitted: (payload) => {
      var submittedReview = payload.review;
      var repository = payload.repository;
      var pullRequest = payload.pull_request;

      return PullRequest.getAllReviews(
        repository.owner.login,
        repository.name,
        pullRequest.number
      ).then((reviews) => {
        var submittingUser = submittedReview.user.id;
        var reviewId = submittedReview.id;
        var promises = [];

        if (submittedReview.state === 'approved' || submittedReview.state === 'changes_requested') {
          for (const review of reviews) {
            if (review.user.id === submittingUser && review.id !== reviewId && (review.state === 'APPROVED' || review.state === 'CHANGES_REQUESTED')) {
              promises.push(PullRequest.dismissReview(repository, pullRequest, review, `Superseded by [${submittedReview.id}](${submittedReview.html_url})`));
            }
          }
        }

        return Q.all(promises);
      }).catch((rejectReason) => {
        console.log(rejectReason);
      }).then(() => {
        return Repository.applyApprovalStatus(repository, pullRequest);
      });
    }
  }
};

var Repository = {
  applyApprovalStatus: (repository, pullRequest) => {
    return PullRequest.getAllReviews(
      repository.owner.login,
      repository.name,
      pullRequest.number
    ).then((reviews) => {
      var changesRequestedCount = 0;
      var approvedCount = 0;

      for (const review of reviews) {
        switch (review.state) {
          case 'APPROVED':
            approvedCount += 1;
            break;
          case 'CHANGES_REQUESTED':
            changesRequestedCount += 1;
            break;
          default:
            break;
        }
      }

      var state;
      if (approvedCount >= requiredApprovalCount && changesRequestedCount === 0) {
        state = 'success';
      } else if (changesRequestedCount === 0) {
        state = 'pending';
      } else {
        state = 'failure';
      }

      //Create status
      return github.repos.createStatus({
        owner: repository.owner.login,
        repo: repository.name,
        sha: pullRequest.head.sha,
        state: state,
        description: `${approvedCount} (of ${requiredApprovalCount}) approval(s), ${changesRequestedCount} change(s) requested`,
        context: 'krush/review'
      }).catch((reason) => {
        console.log(reason);
      });
    });
  }
};

var PullRequest = {
  getAllReviews: (owner, repo, number) => {
    var allReviews = [];
    var getReviews;

    function pager(response) {
      allReviews = allReviews.concat(response);

      if (github.hasNextPage(response)) {
        return github.getNextPage(response, {
          'Accept': 'application/vnd.github.black-cat-preview+json'
        }).then(pager);
      }

      return Q(allReviews);
    }

    return PullRequest.getReviews(owner, repo, number).then(pager);
  },
  getReviews: (owner, repo, number) => {
    github.authenticate({
      type: "oauth",
      token: oauthToken
    });

    return github.pullRequests.getReviews({
      owner,
      repo,
      number,
      page: undefined,
      per_page: 100
    });
  },
  dismissReview: (repository, pullRequest, review, reason) => {
    github.authenticate({
      type: "oauth",
      token: oauthToken
    });

    if (!reason) {
      reason = "New commit to PR";
    }

    return github.pullRequests.dismissReview({
      owner: repository.owner.login,
      repo: repository.name,
      number: pullRequest.number,
      id: review.id,
      message: `Krush/Review: ${reason}`
    });
  }
};

app.post('/incoming', [verifyIp, parseJsonWithHmac, function (request, response) {
  var event = request.get('X-GitHub-Event');
  if (!event) {
    response.sendStatus(500);
    return;
  }

  switch (event) {
    case 'pull_request':
      Webhook.PullRequest.process(request.body).then(() => {
        response.sendStatus(200);
      });
      break;
    case 'pull_request_review':
      Webhook.PullRequestReview.process(request.body).then(() => {
        response.sendStatus(200);
      });
      break;
    default:
      response.sendStatus(200);
      break;
  }
}]);

app.listen(app.get('port'), function () {
  console.log('Node app is running on port', app.get('port'));
});