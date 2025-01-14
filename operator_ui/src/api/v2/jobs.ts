import * as jsonapi from 'utils/json-api-client'
import { boundMethod } from 'autobind-decorator'
import * as models from 'core/store/models'

export const ENDPOINT = '/v2/jobs'
const RUN_JOB_ENDPOINT = `${ENDPOINT}/:specId/runs`

// Jobs represents the v2 jobs
export class Jobs {
  constructor(private api: jsonapi.Api) {}

  @boundMethod
  public createJobSpec(
    request: models.CreateJobRequest,
  ): Promise<jsonapi.ApiResponse<models.Job>> {
    return this.create(request)
  }

  @boundMethod
  public createJobRunV2(
    id: string,
    pipelineInput: string,
  ): Promise<jsonapi.ApiResponse<null>> {
    return this.post(pipelineInput, { specId: id })
  }

  private create = this.api.createResource<models.CreateJobRequest, models.Job>(
    ENDPOINT,
  )

  private post = this.api.createResource<
    string,
    null,
    {
      specId: string
    }
  >(RUN_JOB_ENDPOINT, true)
}
